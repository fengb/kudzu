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

    pub fn recv(self: Server, buf: []u8, flags: u32) !Datagram {
        var source = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        var addr_len = source.getOsSockLen();
        const MSG_TRUNC = 0x0020;
        const recv_len = try std.os.recvfrom(self.sockfd, buf, flags | MSG_TRUNC, &source.any, &addr_len);
        const data = buf[0..@min(buf.len, recv_len)];
        return Datagram{
            .source = source,
            .destination = self.bind_address,
            .data = data,
            .recv_len = recv_len,
        };
    }
};

pub const Datagram = struct {
    source: std.net.Address,
    destination: std.net.Address,
    data: []const u8,
    recv_len: usize,

    pub fn isTruncated(self: Datagram) bool {
        return self.data.len != self.recv_len;
    }
};
