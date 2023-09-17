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

pub const Message = struct {
    identification: u16,
    flags: Flags,

    questions: []Question,
    answers: []Record,
    authorities: []Record,
    additionals: []Record,

    pub const Question = struct {
        name: []const u8,
        type: u16,
        class: u16,
    };

    pub const Record = struct {
        name: []const u8,
        type: u16,
        class: u16,
        ttl: u32,
        data: []const u8,
    };

    pub const dump = @import("dns/dump.zig").dump;
};

test {
    _ = EncodedMessage;
    _ = @import("dns/dump.zig");
}
