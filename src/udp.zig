const std = @import("std");

pub const Server = struct {
    sockfd: std.os.socket_t,
    bind_address: std.net.Address,

    pub fn init(options: struct {
        address: std.net.Address,
        reuse_address: bool = true,
    }) !Server {
        const sock_flags = std.os.SOCK.DGRAM | std.os.SOCK.CLOEXEC;
        const proto = std.os.IPPROTO.UDP;

        const sockfd = try std.os.socket(options.address.any.family, sock_flags, proto);
        errdefer std.os.closeSocket(sockfd);

        if (options.reuse_address) {
            try std.os.setsockopt(
                sockfd,
                std.os.SOL.SOCKET,
                std.os.SO.REUSEADDR,
                &std.mem.toBytes(@as(c_int, 1)),
            );
        }

        var socklen = options.address.getOsSockLen();
        try std.os.bind(sockfd, &options.address.any, socklen);

        var bind_address: std.net.Address = undefined;
        try std.os.getsockname(sockfd, &bind_address.any, &socklen);
        return Server{
            .sockfd = sockfd,
            .bind_address = bind_address,
        };
    }

    pub fn deinit(self: *Server) void {
        std.os.closeSocket(self.sockfd);
        self.* = undefined;
    }

    pub fn recv(self: Server, buf: []u8, flags: u0) !struct { []const u8, bool } {
        return self.recvfrom(buf, flags, null);
    }

    pub fn recvfrom(self: Server, buf: []u8, flags: u0, source_address: ?std.net.Address) !struct { []const u8, bool } {
        const len = if (source_address) |address|
            try std.os.recvfrom(self.sockfd, buf, flags, @constCast(&address.any), @constCast(&address.getOsSockLen()))
        else
            try std.os.recvfrom(self.sockfd, buf, flags, null, null);

        std.debug.print("{}\n", .{len});
        return .{ buf[0..len], false };
    }
};
