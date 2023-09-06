const std = @import("std");
const udp = @import("udp.zig");

const MDNS_PORT = 5353;

pub fn main() !void {
    var server = try udp.Server.init(.{
        .address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 5353),
    });
    defer server.deinit();

    std.debug.print("Test\n", .{});
    var buf: [0x1000]u8 = undefined;
    _ = try server.recv(&buf, 0);
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
