const std = @import("std");
const dns = @import("../dns.zig");
const decode = @import("decode.zig");

pub fn parseAlloc(allocator: std.mem.Allocator, data: []const u8) !dns.Message {
    const decoded = try dns.decode(data);

    const questions = try parseQuestions(allocator, decoded.iterQuestions());
    errdefer allocator.free(questions);

    const answers = try parseRecords(allocator, decoded.iterAnswers());
    errdefer allocator.free(answers);

    const authorities = try parseRecords(allocator, decoded.iterAuthorities());
    errdefer allocator.free(authorities);

    const additionals = try parseRecords(allocator, decoded.iterAdditionals());
    errdefer allocator.free(additionals);

    return .{
        .identification = decoded.identification,
        .flags = decoded.flags,
        .questions = questions,
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
    };
}

pub fn parseFree(allocator: std.mem.Allocator, msg: dns.Message) void {
    for (msg.questions) |question| {
        allocator.free(question.name);
    }
    allocator.free(msg.questions);

    for (msg.answers) |answer| {
        allocator.free(answer.name);
        allocator.free(answer.data);
    }
    allocator.free(msg.answers);

    for (msg.authorities) |authority| {
        allocator.free(authority.name);
        allocator.free(authority.data);
    }
    allocator.free(msg.authorities);

    for (msg.additionals) |additional| {
        allocator.free(additional.name);
        allocator.free(additional.data);
    }
    allocator.free(msg.additionals);
}

fn parseQuestions(allocator: std.mem.Allocator, iter: ReturnType(decode.Message.iterQuestions)) ![]const dns.Question {
    var iter_ = iter;
    var questions = try std.ArrayListUnmanaged(dns.Question).initCapacity(allocator, iter.remaining);
    errdefer {
        for (questions.items) |question| {
            allocator.free(question.name);
        }
        questions.deinit(allocator);
    }
    while (iter_.next()) |decoded_question| {
        const name = try std.fmt.allocPrint(allocator, "{any}", .{decoded_question.name});
        errdefer allocator.free(name);

        questions.appendAssumeCapacity(.{
            .name = name,
            .type = decoded_question.type,
            .class = decoded_question.type,
        });
    }
    return questions.items;
}

fn parseRecords(allocator: std.mem.Allocator, iter: ReturnType(decode.Message.iterAnswers)) ![]const dns.Record {
    var iter_ = iter;
    var records = try std.ArrayListUnmanaged(dns.Record).initCapacity(allocator, iter.remaining);
    errdefer {
        for (records.items) |record| {
            allocator.free(record.name);
            allocator.free(record.data);
        }
        records.deinit(allocator);
    }
    while (iter_.next()) |decoded_record| {
        const name = try std.fmt.allocPrint(allocator, "{any}", .{decoded_record.name});
        errdefer allocator.free(name);

        const data = try allocator.dupe(u8, decoded_record.data);
        errdefer allocator.free(data);

        records.appendAssumeCapacity(.{
            .name = name,
            .type = decoded_record.type,
            .class = decoded_record.class,
            .ttl = decoded_record.ttl,
            .data = data,
        });
    }
    return records.items;
}

fn ReturnType(comptime func: anytype) type {
    return @typeInfo(@TypeOf(func)).Fn.return_type.?;
}

test parseAlloc {
    {
        const empty_message = [_]u8{0} ** 12;
        const msg = try parseAlloc(std.testing.allocator, &empty_message);
        defer parseFree(std.testing.allocator, msg);

        try std.testing.expectEqual(@as(u16, 0), msg.identification);
        try std.testing.expectEqual(@as(u16, 0), @bitCast(msg.flags));
        try std.testing.expectEqualSlices(dns.Question, msg.questions, &.{});
        try std.testing.expectEqualSlices(dns.Record, msg.answers, &.{});
        try std.testing.expectEqualSlices(dns.Record, msg.authorities, &.{});
        try std.testing.expectEqualSlices(dns.Record, msg.additionals, &.{});
    }
}
