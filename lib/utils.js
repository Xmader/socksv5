// @ts-check

const net = require("net")
const ipv6 = require("ipv6").v6

/**
 * @param {string} str 
 */
const ipbytes = (str) => {

    const type = net.isIP(str)

    let nums
    let bytes
    let i

    if (type === 4) {

        nums = str.split(".", 4)
        bytes = new Array(4)

        for (i = 0; i < 4; ++i) {
            if (isNaN(bytes[i] = +nums[i])) {
                throw new Error("Error parsing IP: " + str)
            }
        }

    } else if (type === 6) {

        const addr = new ipv6.Address(str)
        let b = 0
        let group

        if (!addr.valid) {
            throw new Error("Error parsing IP: " + str)
        }

        nums = addr.parsedAddress
        bytes = new Array(16)

        for (i = 0; i < 8; ++i, b += 2) {
            group = parseInt(nums[i], 16)
            bytes[b] = group >>> 8
            bytes[b + 1] = group & 0xFF
        }
    }

    return bytes
}

exports.ipbytes = ipbytes
