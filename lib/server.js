// @ts-check

const net = require("net")
const dns = require("dns")
const util = require("util")
const { EventEmitter } = require("events")

const Parser = require("./server.parser")
const { ipbytes } = require("./utils")

const { ATYP } = require("./constants")
const { REP } = require("./constants")

const { Transform } = require("stream")

const BUF_AUTH_NO_ACCEPT = new Buffer([0x05, 0xFF])
const BUF_REP_INTR_SUCCESS = new Buffer(
    [
        0x05,
        REP.SUCCESS,
        0x00,
        0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ]
)
const BUF_REP_DISALLOW = new Buffer([0x05, REP.DISALLOW])
const BUF_REP_CMDUNSUPP = new Buffer([0x05, REP.CMDUNSUPP])

const onErrorNoop = (err) => { }

/**
 * @param {net.Socket} socket 
 * @param {*} err 
 */
const handleProxyError = (socket, err) => {
    if (socket.writable) {
        const errbuf = new Buffer([0x05, REP.GENFAIL])

        if (err.code) {
            switch (err.code) {
                case "ENOENT":
                case "ENOTFOUND":
                case "ETIMEDOUT":
                case "EHOSTUNREACH":
                    errbuf[1] = REP.HOSTUNREACH
                    break
                case "ENETUNREACH":
                    errbuf[1] = REP.NETUNREACH
                    break
                case "ECONNREFUSED":
                    errbuf[1] = REP.CONNREFUSED
                    break
            }
        }
        socket.end(errbuf)
    }
}

/**
 * @typedef {typeof import("./auth/None")} Auth
 */

/**
 * @typedef {Object} Options
 * @property { Auth[] } [auths]
 * @property { (str: string) => any } [debug]
 * @property { (data: Buffer) => Buffer } [modifyRequest]
 */

/**
 * @typedef {Object} ConnInfo
 * @property {string} srcAddr 
 * @property {number} srcPort 
 * @property {string} dstAddr 
 * @property {number} dstPort 
 */

/**
 * @typedef { (info: ConnInfo, accept: (intercept?: boolean) => net.Socket, deny: () => void) => void } Listener
 */

/**
 * @param {net.Socket} socket 
 * @param {ConnInfo} req 
 * @param { (data: Buffer) => Buffer } modifyRequest
 */
const proxySocket = (socket, req, modifyRequest) => {
    dns.lookup(req.dstAddr, function (err, dstIP) {

        if (err) {
            handleProxyError(socket, err)
            return
        }

        const dstSock = new net.Socket()
        let connected = false

        const onError = (err) => {
            if (!connected) {
                handleProxyError(socket, err)
            }
        }

        dstSock.setKeepAlive(false)

        dstSock.on("error", onError)

        dstSock.on("connect", () => {

            connected = true

            if (socket.writable) {

                const localbytes = ipbytes(dstSock.localAddress || "127.0.0.1")
                const len = localbytes.length
                const bufrep = new Buffer(6 + len)

                let p = 4

                bufrep[0] = 0x05
                bufrep[1] = REP.SUCCESS
                bufrep[2] = 0x00
                bufrep[3] = (len === 4 ? ATYP.IPv4 : ATYP.IPv6)

                for (let i = 0; i < len; ++i, ++p) {
                    bufrep[p] = localbytes[i]
                }

                bufrep.writeUInt16BE(dstSock.localPort, p, true)

                const transform = new Transform()
                transform._transform = (data, encoding, callback) => {
                    data = modifyRequest(data)
                    callback(null, data)
                }

                socket.write(bufrep)
                socket.pipe(transform).pipe(dstSock).pipe(socket)
                socket.resume()

            } else if (dstSock.writable) {
                dstSock.end()
            }
        })

        dstSock.connect(req.dstPort, dstIP)

        socket.dstSock = dstSock
    })
}

class Server extends EventEmitter {

    /**
     * @param {Options} options 
     * @param {Listener} listener 
     */
    constructor(options, listener) {
        super()

        if (typeof options === "function") {
            this.on("connection", options)
            options = undefined
        } else if (typeof listener === "function") {
            this.on("connection", listener)
        }

        this._srv = new net.Server((socket) => {

            if (this._connections >= this.maxConnections) {
                socket.destroy()
                return
            }

            ++this._connections

            socket.once("close", (had_err) => {
                --this._connections
            })

            this._onConnection(socket)

        }).on("error", (err) => {
            this.emit("error", err)
        }).on("listening", () => {
            this.emit("listening")
        }).on("close", () => {
            this.emit("close")
        })

        this._auths = []

        if (options && Array.isArray(options.auths)) {
            for (let i = 0, len = options.auths.length; i < len; ++i) {
                this.useAuth(options.auths[i])
            }
        }

        this.modifyRequest = options.modifyRequest
        if (!this.modifyRequest || typeof this.modifyRequest !== "function") {
            this.modifyRequest = (data) => data
        }

        this._debug = (options && typeof options.debug === "function") && options.debug

        this._connections = 0
        this.maxConnections = Infinity

    }

    /**
     * @param {net.Socket} socket 
     */
    _onConnection(socket) {

        const parser = new Parser(socket)

        parser.on("error", () => {
            if (socket.writable) {
                socket.end()
            }
        }).on("methods", (methods) => {
            const auths = this._auths

            for (let a = 0, alen = auths.length; a < alen; ++a) {
                for (let m = 0, mlen = methods.length; m < mlen; ++m) {
                    if (methods[m] === auths[a].METHOD) {

                        auths[a].server(socket, (result) => {
                            if (result === true) {
                                parser.authed = true
                                parser.start()
                            } else {
                                if (util.isError(result))
                                    this._debug && this._debug("Error: " + result.message);
                                socket.end()
                            }
                        })

                        socket.write(new Buffer([0x05, auths[a].METHOD]))
                        socket.resume()

                        return
                    }
                }
            }

            socket.end(BUF_AUTH_NO_ACCEPT)

        }).on("request", (reqInfo) => {

            if (reqInfo.cmd !== "connect") {
                return socket.end(BUF_REP_CMDUNSUPP)
            }

            reqInfo.srcAddr = socket.remoteAddress
            reqInfo.srcPort = socket.remotePort

            let handled = false

            /**
             * @param {boolean} intercept 
             */
            const accept = (intercept) => {

                if (handled) {
                    return
                }

                handled = true

                if (socket.writable) {

                    if (intercept) {
                        socket.write(BUF_REP_INTR_SUCCESS)
                        socket.removeListener("error", onErrorNoop)
                        process.nextTick(() => {
                            socket.resume()
                        })
                    } else {
                        proxySocket(socket, reqInfo, this.modifyRequest)
                    }

                    return socket
                }
            }

            const deny = () => {

                if (handled) {
                    return
                }

                handled = true

                if (socket.writable) {
                    socket.end(BUF_REP_DISALLOW)
                }

            }

            if (this._events.connection) {
                this.emit("connection", reqInfo, accept, deny)
                return
            }

            proxySocket(socket, reqInfo, this.modifyRequest)
        })

        const onClose = () => {
            if (socket.dstSock && socket.dstSock.writable) {
                socket.dstSock.end()
            }
            socket.dstSock = undefined
        }

        socket.on("error", onErrorNoop)
            .on("end", onClose)
            .on("close", onClose)
    }

    useAuth(auth) {
        if (
            typeof auth !== "object"
            || typeof auth.server !== "function"
            || auth.server.length !== 2
        ) {
            throw new Error("Invalid authentication handler")
        } else if (this._auths.length >= 255) {
            throw new Error("Too many authentication handlers (limited to 255).")
        }

        this._auths.push(auth)

        return this
    }

    listen() {
        this._srv.listen.apply(this._srv, arguments)
        return this
    }

    address() {
        return this._srv.address()
    }

    getConnections(cb) {
        this._srv.getConnections(cb)
    }

    close(cb) {
        this._srv.close(cb)
        return this
    }

    ref() {
        this._srv.ref()
    }

    unref() {
        this._srv.unref()
    }
}


exports.Server = Server

/**
 * @param {Options} opts 
 * @param {Listener} listener 
 */
exports.createServer = (opts, listener) => {
    return new Server(opts, listener)
}
