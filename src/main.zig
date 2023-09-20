const std = @import("std");
const udp = @import("udp.zig");
const dns = @import("dns.zig");

const MDNS_ADDR = [_]u8{ 224, 0, 0, 251 };
const MDNS_PORT = 5353;

pub fn main() !void {
    var server = try udp.Server.init(.{
        .address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 5353),
    });
    defer server.deinit();
    try server.addMembership(MDNS_ADDR);

    std.debug.print("Bind {}\n", .{server.bind_address});

    var buf: [0x1000]u8 = undefined;
    while (true) {
        const datagram = try server.recv(&buf, 0);
        const message = try dns.decode(datagram.data);
        std.debug.print("{}\n", .{message});
    }
}

test {
    _ = udp;
    _ = dns;
}
