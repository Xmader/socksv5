
exports.CMD = {
    CONNECT: 0x01,
    BIND: 0x02,
    UDP: 0x03
}

exports.ATYP = {
    IPv4: 0x01,
    NAME: 0x03,
    IPv6: 0x04
}

exports.REP = {
    SUCCESS: 0x00,
    GENFAIL: 0x01,
    DISALLOW: 0x02,
    NETUNREACH: 0x03,
    HOSTUNREACH: 0x04,
    CONNREFUSED: 0x05,
    TTLEXPIRED: 0x06,
    CMDUNSUPP: 0x07,
    ATYPUNSUPP: 0x08
}
