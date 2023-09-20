const std = @import("std");
pub const decode = @import("dns/decode.zig").decode;
pub const encode = @import("dns/encode.zig").encode;
const parse = @import("dns/parse.zig");

pub const parseAlloc = parse.parseAlloc;
pub const parseFree = parse.parseFree;

pub const Flags = packed struct(u16) {
    qr: enum(u1) { query = 0, response = 1 },
    opcode: u4,
    authoritative_answer: bool,
    is_truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    zero: u1,
    authentic_data: bool,
    checking_disabled: bool,
    rcode: u4,
};

pub const Message = struct {
    identification: u16,
    flags: Flags,

    questions: []const Question,
    answers: []const Record,
    authorities: []const Record,
    additionals: []const Record,
};

pub const Question = struct {
    name: []const u8,
    type: ResourceType,
    class: u16,
};

pub const Record = struct {
    name: []const u8,
    type: ResourceType,
    class: u16,
    ttl: u32,
    data: []const u8,
};

pub const ResourceType = enum(u16) {
    A = 1,
    AAAA = 28,
    AFSDB = 18,
    APL = 42,
    CAA = 257,
    CDNSKEY = 60,
    CDS = 59,
    CERT = 37,
    CNAME = 5,
    CSYNC = 62,
    DHCID = 49,
    DLV = 32769,
    DNAME = 39,
    DNSKEY = 48,
    DS = 43,
    EUI48 = 108,
    EUI64 = 109,
    HINFO = 13,
    HIP = 55,
    HTTPS = 65,
    IPSECKEY = 45,
    KEY = 25,
    KX = 36,
    LOC = 29,
    MX = 15,
    NAPTR = 35,
    NS = 2,
    NSEC = 47,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    OPENPGPKEY = 61,
    PTR = 12,
    RRSIG = 46,
    RP = 17,
    SIG = 24,
    SMIMEA = 53,
    SOA = 6,
    SRV = 33,
    SSHFP = 44,
    SVCB = 64,
    TA = 32768,
    TKEY = 249,
    TLSA = 52,
    TSIG = 250,
    TXT = 16,
    URI = 256,
    ZONEMD = 63,
    _,
};

test {
    _ = decode;
    _ = encode;
    _ = parse;
}
