const std = @import("std");
pub const EncodedMessage = @import("dns/EncodedMessage.zig");

pub const parse = EncodedMessage.parse;

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

test {
    _ = EncodedMessage;
}
