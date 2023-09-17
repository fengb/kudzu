const std = @import("std");
pub const decode = @import("dns/decode.zig").decode;
pub const encode = @import("dns/encode.zig").encode;

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
};

test {
    _ = decode;
    _ = encode;
}
