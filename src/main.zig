const std = @import("std");
const udp = @import("udp.zig");
const dns = @import("dns.zig");

const MDNS_ADDR = [_]u8{ 224, 0, 0, 251 };
const MDNS_PORT = 5353;
const SEND_ADDR = std.net.Address.initIp4(MDNS_ADDR, MDNS_PORT);

pub fn main() !void {
    var server = try udp.Server.init(.{
        .address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 5353),
    });
    defer server.deinit();
    try server.addMembership(MDNS_ADDR);

    const send_sock = try std.os.socket(std.os.AF.INET, std.os.SOCK.DGRAM | std.os.SOCK.CLOEXEC, std.os.IPPROTO.UDP);
    defer std.os.closeSocket(send_sock);

    std.debug.print("Bind {}\n", .{server.bind_address});

    var buf: [0x1000]u8 = undefined;
    while (true) {
        const datagram = try server.recv(&buf, 0);
        const message = try dns.decode(datagram.data);
        std.debug.print("{}\n", .{message});

        var questions = message.iterQuestions();
        while (questions.next()) |question| {
            if (question.name.equiv("foobar.local")) {
                try postMessage(.{
                    .identification = 0,
                    .flags = .{
                        .qr = .response,
                        .opcode = 0,
                        .authoritative_answer = false,
                        .is_truncated = false,
                        .recursion_desired = false,
                        .recursion_available = false,
                        .zero = 0,
                        .authentic_data = false,
                        .checking_disabled = false,
                        .rcode = u4,
                    },

                    .questions = &.{},
                    .answers = &.{},
                    .authorities = &.{},
                    .additionals = &.{},
                });
            }
        }
    }
}

fn postMessage(sock: std.os.fd, msg: dns.Message) !void {
    var buf: [512]u8 = undefined;
    const data = try dns.encode(msg, &buf);

    const flags = 0;
    try std.os.sendto(sock, data, flags, &SEND_ADDR, SEND_ADDR.getOsSockLen());
}

test {
    _ = udp;
    _ = dns;
}
