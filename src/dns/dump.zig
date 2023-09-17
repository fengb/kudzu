const std = @import("std");
const dns = @import("../dns.zig");

pub fn dump(msg: dns.Message, buffer: []u8) ![]const u8 {
    var ctx = Context.init(buffer);
    const writer = ctx.fbs.writer();

    try writer.writeIntBig(u16, msg.identification);
    try writer.writeStruct(msg.flags);
    try writer.writeIntBig(u16, @intCast(msg.questions.len));
    try writer.writeIntBig(u16, @intCast(msg.answers.len));
    try writer.writeIntBig(u16, @intCast(msg.authorities.len));
    try writer.writeIntBig(u16, @intCast(msg.additionals.len));

    std.debug.assert(ctx.fbs.pos == 12);
    for (msg.questions) |question| {
        try ctx.writeName(question.name);
        try writer.writeIntBig(u16, question.type);
        try writer.writeIntBig(u16, question.class);
    }

    for (msg.answers) |answer| {
        try ctx.writeRecord(answer);
    }

    for (msg.authorities) |authority| {
        try ctx.writeRecord(authority);
    }

    for (msg.additionals) |additional| {
        try ctx.writeRecord(additional);
    }
    return ctx.fbs.getWritten();
}

fn findDnsSeparator(string: []const u8) ?usize {
    for (string, 0..) |char, i| {
        if (char < '0') {
            return i;
        }
    }
    return null;
}

fn splitDns(name: []const u8) struct { []const u8, []const u8 } {
    if (findDnsSeparator(name)) |len| {
        return .{ name[0..len], name[len + 1 ..] };
    } else {
        return .{ name, name[name.len..] };
    }
}

const Context = struct {
    fbs: std.io.FixedBufferStream([]u8),
    name_cache: std.BoundedArray(NameCache, 64) = .{},

    const NameCache = struct {
        name: []const u8,
        start: u16,
    };

    fn init(buffer: []u8) Context {
        return .{
            .fbs = std.io.fixedBufferStream(buffer),
            .name_cache = .{},
        };
    }

    fn shouldCache(name: []const u8) bool {
        return name.len > 6;
    }

    fn findNameCache(ctx: Context, name: []const u8) ?NameCache {
        for (ctx.name_cache.slice()) |entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                return entry;
            }
        }
        return null;
    }

    fn writeName(ctx: *Context, name: []const u8) !void {
        const writer = ctx.fbs.writer();

        if (name.len == 0) {
            try writer.writeByte(0);
            return;
        }

        if (ctx.findNameCache(name)) |entry| {
            const data = entry.start | 0xc000;
            try writer.writeIntBig(u16, data);
            return;
        }

        if (shouldCache(name)) {
            ctx.name_cache.append(.{ .name = name, .start = @intCast(ctx.fbs.pos) }) catch |err| switch (err) {
                error.Overflow => {}, // No space left. Ignore!
            };
        }
        const segment, const rest = splitDns(name);
        try writer.writeIntBig(u16, @intCast(segment.len));
        try writer.writeAll(segment);
        return ctx.writeName(rest);
    }

    fn writeRecord(ctx: *Context, record: dns.Message.Record) !void {
        const writer = ctx.fbs.writer();
        try ctx.writeName(record.name);
        try writer.writeIntBig(u16, record.type);
        try writer.writeIntBig(u16, record.class);
        try writer.writeIntBig(u32, record.ttl);
        try writer.writeIntBig(u16, @intCast(record.data.len));
        try writer.writeAll(record.data);
    }
};

test splitDns {
    {
        const segment, const rest = splitDns("www.google.com");
        try std.testing.expectEqualStrings("www", segment);
        try std.testing.expectEqualStrings("google.com", rest);
    }
    {
        const segment, const rest = splitDns("google.com");
        try std.testing.expectEqualStrings("google", segment);
        try std.testing.expectEqualStrings("com", rest);
    }
    {
        const result = splitDns("com");
        try std.testing.expectEqualStrings("com", result[0]);
        try std.testing.expectEqualStrings("", result[1]);
    }
}

test dump {
    var buf: [0x1000]u8 = undefined;
    {
        const msg = dns.Message{
            .identification = 42,
            .flags = undefined,
            .questions = &.{},
            .answers = &.{},
            .authorities = &.{},
            .additionals = &.{},
        };
        const result = try dump(msg, &buf);

        try std.testing.expectEqual(@as(usize, 12), result.len);
        // Yay big endian
        try std.testing.expectEqual(@as(u8, 0), result[0]);
        try std.testing.expectEqual(@as(u8, 42), result[1]);

        // All counts are zero
        try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 8, result[4..12]);
    }
}
