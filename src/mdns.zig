const std = @import("std");

pub const Message = struct {
    pub fn parse(data: []const u8) ?Message {
        const base_message = DnsMessage.parse(data);
        return base_message;
    }
};

pub const DnsMessage = struct {
    identification: u16,
    flags: packed struct(u16) {
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
    },
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,

    payload: []const u8,

    pub fn parse(data: []const u8) DnsMessage {
        return .{
            .identification = std.mem.readIntBig(u16, data[0..2]),
            .flags = @bitCast(data[2..4].*),
            .question_count = std.mem.readIntBig(u16, data[4..6]),
            .answer_record_count = std.mem.readIntBig(u16, data[6..8]),
            .authority_record_count = std.mem.readIntBig(u16, data[8..10]),
            .additional_record_count = std.mem.readIntBig(u16, data[10..12]),

            .payload = data[12..],
        };
    }
};

pub const EncodedString = struct {
    data: []const u8,

    pub fn readFirst(stream: *std.io.FixedBufferStream([]const u8)) !EncodedString {
        const start = stream.pos;
        while (try Iterator.nextRaw(stream)) |_| {
            // TODO: maybe detect ASCII
        }
        if (stream.pos > stream.buffer.len) {
            return error.EndOfStream;
        }

        return EncodedString{ .data = stream.buffer[start..stream.pos] };
    }

    pub fn iterSegments(self: EncodedString) Iterator {
        return Iterator{ .fbs = std.io.fixedBufferStream(self.data) };
    }

    const Iterator = struct {
        fbs: std.io.FixedBufferStream([]const u8),

        pub fn next(iter: *Iterator) ?[]const u8 {
            return nextRaw(&iter.fbs) catch unreachable;
        }

        fn nextRaw(fbs: *std.io.FixedBufferStream([]const u8)) !?[]const u8 {
            const reader = fbs.reader();

            const segment_length = try reader.readByte();
            if (segment_length == 0) {
                return null;
            }

            const start = fbs.pos;
            try reader.skipBytes(segment_length, .{});
            return fbs.buffer[start..fbs.pos];
        }
    };

    pub fn format(
        self: EncodedString,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var iter = self.iterSegments();

        const first = iter.next() orelse return;
        try writer.writeAll(first);

        while (iter.next()) |segment| {
            try writer.print(".{s}", .{segment});
        }
    }
};

test EncodedString {
    var fbs = std.io.fixedBufferStream("\x03www\x0dxyzindustries\x03com\x00");
    var buffer: [0x1000]u8 = undefined;

    const es = try EncodedString.readFirst(&fbs);
    try std.testing.expectEqualStrings("www.xyzindustries.com", try std.fmt.bufPrint(&buffer, "{}", .{es}));
}
