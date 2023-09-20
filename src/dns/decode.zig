const std = @import("std");
const dns = @import("../dns.zig");

pub fn decode(data: []const u8) !Message {
    const msg_stub: Message = undefined;

    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    const identification = try reader.readIntBig(u16);
    const flags = try reader.readStruct(dns.Flags);
    const question_count = try reader.readIntBig(u16);
    const answer_record_count = try reader.readIntBig(u16);
    const authority_record_count = try reader.readIntBig(u16);
    const additional_record_count = try reader.readIntBig(u16);

    std.debug.assert(msg_stub.question_start == fbs.pos);
    for (0..question_count) |_| {
        _ = try Question.read(&fbs);
    }

    const answer_record_start = fbs.pos;
    for (0..answer_record_count) |_| {
        _ = try Record.read(&fbs);
    }

    const authority_record_start = fbs.pos;
    for (0..authority_record_count) |_| {
        _ = try Record.read(&fbs);
    }

    const additional_record_start = fbs.pos;
    for (0..additional_record_count) |_| {
        _ = try Record.read(&fbs);
    }

    return .{
        .identification = identification,
        .flags = flags,
        .question_count = question_count,
        .answer_record_count = answer_record_count,
        .authority_record_count = authority_record_count,
        .additional_record_count = additional_record_count,

        .raw = data,
        .answer_record_start = answer_record_start,
        .authority_record_start = authority_record_start,
        .additional_record_start = additional_record_start,
    };
}

pub const Message = struct {
    // Header
    identification: u16,
    flags: dns.Flags,
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,

    raw: []const u8,
    comptime question_start: comptime_int = 12,
    answer_record_start: usize,
    authority_record_start: usize,
    additional_record_start: usize,

    pub fn iterQuestions(self: Message) Iterator(Question) {
        return Iterator(Question).init(self.raw, self.question_start, self.question_count);
    }

    pub fn iterAnswers(self: Message) Iterator(Record) {
        return Iterator(Record).init(self.raw, self.answer_record_start, self.answer_record_count);
    }

    pub fn iterAuthorities(self: Message) Iterator(Record) {
        return Iterator(Record).init(self.raw, self.authority_record_start, self.authority_record_count);
    }

    pub fn iterAdditionals(self: Message) Iterator(Record) {
        return Iterator(Record).init(self.raw, self.additional_record_start, self.additional_record_count);
    }

    fn Iterator(comptime T: type) type {
        return struct {
            fbs: std.io.FixedBufferStream([]const u8),
            remaining: usize,

            fn init(raw: []const u8, start: usize, total: usize) @This() {
                var fbs = std.io.fixedBufferStream(raw);
                fbs.seekTo(start) catch unreachable;
                return .{ .fbs = fbs, .remaining = total };
            }

            pub fn next(self: *@This()) ?T {
                if (self.remaining == 0) {
                    return null;
                }
                self.remaining -= 1;

                return T.read(&self.fbs) catch unreachable;
            }
        };
    }
};

pub const Question = struct {
    name: String,
    type: dns.ResourceType,
    class: u16,

    fn read(fbs: *std.io.FixedBufferStream([]const u8)) !Question {
        const reader = fbs.reader();

        return Question{
            .name = try String.readFirst(fbs),
            .type = @enumFromInt(try reader.readIntBig(u16)),
            .class = try reader.readIntBig(u16),
        };
    }
};

pub const Record = struct {
    name: String,
    type: dns.ResourceType,
    class: u16,
    ttl: u32,
    data: []const u8,

    fn read(fbs: *std.io.FixedBufferStream([]const u8)) !Record {
        const reader = fbs.reader();

        return Record{
            .name = try String.readFirst(fbs),
            .type = @enumFromInt(try reader.readIntBig(u16)),
            .class = try reader.readIntBig(u16),
            .ttl = try reader.readIntBig(u32),
            .data = blk: {
                const length = try reader.readIntBig(u16);
                const start = fbs.pos;
                try reader.skipBytes(length, .{});
                break :blk fbs.buffer[start..][0..length];
            },
        };
    }
};

const String = struct {
    data: []const u8,
    start: usize,

    pub fn readFirst(stream: *std.io.FixedBufferStream([]const u8)) !String {
        const start = stream.pos;
        var end_index: usize = 0;
        while (try Iterator.nextRaw(stream, &end_index)) |_| {
            // TODO: validate ASCII
        }
        if (end_index > 0) {
            stream.pos = end_index;
        }
        if (stream.pos > stream.buffer.len) {
            return error.EndOfStream;
        }

        return String{ .data = stream.buffer, .start = start };
    }

    /// Returns true if this is equivalent to a real string
    /// Since DNS does not encode non-alphanumeric, it's never *really* equal
    /// e.g. john@gmail.com has the same wire format as john.gmail.com
    pub fn equiv(self: String, other: []const u8) bool {
        var remaining = other;
        var iter = self.iterSegments();

        const first = iter.next() orelse return remaining.len == 0;
        if (!std.mem.startsWith(u8, remaining, first)) {
            return false;
        }
        remaining = remaining[first.len..];
        while (iter.next()) |segment| {
            if (remaining.len < 0 or !isDnsSeparator(remaining[0])) {
                return false;
            }
            remaining = remaining[1..];

            if (!std.mem.startsWith(u8, remaining, segment)) {
                return false;
            }
            remaining = remaining[segment.len..];
        }
        return remaining.len == 0;
    }

    pub fn iterSegments(self: String) Iterator {
        var fbs = std.io.fixedBufferStream(self.data);
        fbs.seekTo(self.start) catch unreachable;
        return Iterator{ .fbs = fbs };
    }

    const Iterator = struct {
        fbs: std.io.FixedBufferStream([]const u8),

        pub fn next(iter: *Iterator) ?[]const u8 {
            var ignore: usize = 69;
            return nextRaw(&iter.fbs, &ignore) catch unreachable;
        }

        fn nextRaw(fbs: *std.io.FixedBufferStream([]const u8), end_index: *usize) !?[]const u8 {
            const reader = fbs.reader();

            switch (try reader.readByte()) {
                0x00 => return null,
                0x01...0xBF => |segment_length| {
                    const start = fbs.pos;
                    try reader.skipBytes(segment_length, .{});
                    return fbs.buffer[start..fbs.pos];
                },
                0xC0...0xFF => |first_byte| {
                    const second_byte = try reader.readByte();
                    const target_position = @as(u16, first_byte & 0x3F) << 8 | second_byte;
                    if (end_index.* == 0) {
                        end_index.* = fbs.pos;
                    }
                    try fbs.seekTo(target_position);
                    return nextRaw(fbs, end_index);
                },
            }
        }
    };

    pub fn format(
        self: String,
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

fn isDnsSeparator(char: u8) bool {
    return switch (char) {
        '0'...'9',
        'A'...'Z',
        'a'...'z',
        '_',
        => false,
        else => true,
    };
}

test String {
    var buffer: [0x1000]u8 = undefined;
    {
        var fbs = std.io.fixedBufferStream("\x03www\x0dxyzindustries\x03com\x00");
        const es = try String.readFirst(&fbs);
        try std.testing.expectEqualStrings("www.xyzindustries.com", try std.fmt.bufPrint(&buffer, "{}", .{es}));
    }

    {
        var fbs = std.io.fixedBufferStream("\x03www\x03abc\x03xyz\x00" ++
            // Compression support: 11xxxxxx yyyyyyyy
            // Use the same value at position xxxxxxyyyyyyyy
            "\xc0\x04" ++
            // Prefix followed by compression
            "\x02qq\xc0\x04");

        const es1 = try String.readFirst(&fbs);
        try std.testing.expectEqualStrings("www.abc.xyz", try std.fmt.bufPrint(&buffer, "{}", .{es1}));

        // Ensure the fbs is reading in the correct location
        try std.testing.expectEqual(@as(u8, 0xc0), fbs.buffer[fbs.pos]);
        const es2 = try String.readFirst(&fbs);
        try std.testing.expectEqualStrings("abc.xyz", try std.fmt.bufPrint(&buffer, "{}", .{es2}));

        // Ensure the fbs is reading in the correct location
        try std.testing.expectEqual(@as(u8, 0x02), fbs.buffer[fbs.pos]);
        const es3 = try String.readFirst(&fbs);
        try std.testing.expectEqualStrings("qq.abc.xyz", try std.fmt.bufPrint(&buffer, "{}", .{es3}));
    }
}

test "String.equiv" {
    var fbs = std.io.fixedBufferStream("\x03www\x0dxyzindustries\x03com\x00");
    const str = try String.readFirst(&fbs);
    try std.testing.expect(str.equiv("www.xyzindustries.com"));
    try std.testing.expect(str.equiv("www@xyzindustries.com"));
    try std.testing.expect(!str.equiv("foo.bar"));
    try std.testing.expect(!str.equiv("www@xyzindustries.comm"));
    try std.testing.expect(!str.equiv("www@xyz"));
}

test Message {
    var buffer: [0x1000]u8 = undefined;
    {
        const questions1 = @embedFile("../test-data/questions1.dns");
        const message = try decode(questions1);

        try std.testing.expectEqual(@as(usize, 2), message.question_count);
        var iter = message.iterQuestions();

        const question1 = iter.next() orelse return error.NotEnoughQuestions;
        try std.testing.expectEqual(dns.ResourceType.A, question1.type);
        try std.testing.expectEqualStrings("foobar.local", try std.fmt.bufPrint(&buffer, "{}", .{question1.name}));

        const question2 = iter.next() orelse return error.NotEnoughQuestions;
        try std.testing.expectEqual(dns.ResourceType.AAAA, question2.type);
        try std.testing.expectEqualStrings("foobar.local", try std.fmt.bufPrint(&buffer, "{}", .{question2.name}));

        try std.testing.expectEqual(iter.next(), null);
    }

    {
        const questions2 = @embedFile("../test-data/questions2.dns");
        const message = try decode(questions2);

        {
            var iter = message.iterQuestions();
            while (iter.next()) |question| {
                std.debug.print("{any}\n", .{question});
            }
        }

        {
            std.debug.print("--ANSWERS--\n", .{});
            var iter = message.iterAnswers();
            while (iter.next()) |answer| {
                std.debug.print("{any}\n", .{answer});
            }
        }
    }
}
