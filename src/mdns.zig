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
    data: [:0]const u8,

    pub fn parseFirst(data: []const u8) !EncodedString {
        var iter = Iterator{ .data = data, .cursor = 0 };
        while (iter.next()) |_| {
            // TODO: maybe detect ASCII
        }
        if (iter.cursor >= data.len) {
            return error.EndOfStream;
        }
        if (data[iter.cursor] != 0) {
            return error.ParseFailure;
        }

        return EncodedString{ .data = data[0..iter.cursor :0] };
    }

    pub fn iterSegments(self: EncodedString) Iterator {
        return Iterator{ .data = self.data, .cursor = 0 };
    }

    const Iterator = struct {
        data: []const u8,
        cursor: usize,

        pub fn next(iter: *Iterator) ?[]const u8 {
            if (iter.cursor >= iter.data.len) {
                // EndOfStream. This is an error if the underlying data isn't null terminated, but we check that elsewhere.
                return null;
            }

            const segment_length = iter.data[iter.cursor];
            if (segment_length == 0) {
                return null;
            }

            iter.cursor += 1;
            const start = iter.cursor;
            iter.cursor += segment_length;
            if (iter.cursor > iter.data.len) {
                // Broken parse. This is an error but only the parser should throw an error.
                return null;
            }
            return iter.data[start..iter.cursor];
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
    var buffer: [0x1000]u8 = undefined;

    const es = try EncodedString.parseFirst("\x03www\x0dxyzindustries\x03com\x00");
    try std.testing.expectEqualStrings("www.xyzindustries.com", try std.fmt.bufPrint(&buffer, "{}", .{es}));
}
