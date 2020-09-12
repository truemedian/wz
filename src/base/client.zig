const std = @import("std");
const base64 = std.base64;
const ascii = std.ascii;
const time = std.time;
const rand = std.rand;
const fmt = std.fmt;
const mem = std.mem;

const http = std.http;

const Sha1 = std.crypto.hash.Sha1;
const assert = std.debug.assert;

usingnamespace @import("common.zig");

pub fn create(buffer: []u8, reader: anytype, writer: anytype) Client(@TypeOf(reader), @TypeOf(writer)) {
    assert(buffer.len >= 16);

    return Client(@TypeOf(reader), @TypeOf(writer)).init(buffer, reader, writer);
}

const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const handshake_key_length = 16;

fn checkHandshakeKey(original: []const u8, recieved: []const u8) bool {
    var hash = Sha1.init(.{});
    hash.update(original);
    hash.update(websocket_guid);

    var hashed_key: [Sha1.digest_length]u8 = undefined;
    hash.final(&hashed_key);

    var encoded: [base64.Base64Encoder.calcSize(Sha1.digest_length)]u8 = undefined;
    base64.standard_encoder.encode(&encoded, &hashed_key);

    return mem.eql(u8, &encoded, recieved);
}

inline fn extractMaskByte(mask: u32, index: usize) u8 {
    return @truncate(u8, mask >> @truncate(u5, (index % 4) * 8));
}

pub fn Client(comptime Reader: type, comptime Writer: type) type {
    const ReaderError = if (@typeInfo(Reader) == .Pointer) @typeInfo(Reader).Pointer.child.Error else Reader.Error;
    const WriterError = if (@typeInfo(Writer) == .Pointer) @typeInfo(Writer).Pointer.child.Error else Writer.Error;

    const HzzpClient = hzzp.Client.Client(Reader, Writer);

    return struct {
        const Self = @This();

        read_buffer: []u8,
        prng: rand.DefaultPrng,

        reader: Reader,
        writer: Writer,

        handshaken: bool = false,
        handshake_client: HzzpClient,
        handshake_key: [base64.Base64Encoder.calcSize(handshake_key_length)]u8 = undefined,

        current_mask: ?u32 = null,
        mask_index: usize = 0,

        chunk_need: usize = 0,
        chunk_read: usize = 0,
        chunk_mask: ?u32 = undefined,

        state: ParserState = .header,

        pub fn init(buffer: []u8, reader: Reader, writer: Writer) Self {
            return Self{
                .read_buffer = buffer,
                .handshake_client = hzzp.Client.create(buffer, reader, writer),
                .prng = rand.DefaultPrng.init(@bitCast(u64, time.milliTimestamp())),
                .reader = reader,
                .writer = writer,
            };
        }

        pub fn sendHandshakeHead(self: *Self, path: []const u8) WriterError!void {
            var raw_key: [handshake_key_length]u8 = undefined;
            self.prng.random.bytes(&raw_key);

            base64.standard_encoder.encode(&self.handshake_key, &raw_key);

            self.handshake_client.reset();
            try self.handshake_client.writeHead("GET", path);

            try self.handshake_client.writeHeaderValue("Connection", "Upgrade");
            try self.handshake_client.writeHeaderValue("Upgrade", "websocket");
            try self.handshake_client.writeHeaderValue("Sec-WebSocket-Version", "13");
            try self.handshake_client.writeHeaderValue("Sec-WebSocket-Key", &self.handshake_key);
        }

        pub fn sendHandshakeHeaderValue(self: *Self, name: []const u8, value: []const u8) WriterError!void {
            return self.handshake_client.writeHeaderValue(name, value);
        }

        pub fn sendHandshakeHeader(self: *Self, header: hzzp.Header) WriterError!void {
            return self.handshake_client.writeHeader(header);
        }

        pub fn sendHandshakeHeaderArray(self: *Self, headers: hzzp.Headers) WriterError!void {
            return self.handshake_client.writeHeaders(headers);
        }

        pub fn sendHandshakeStdHeaders(self: *Self, headers: *http.Headers) WriterError!void {
            for (headers.toSlice()) |entry| {
                try self.handshake_client.writeHeaderValue(entry.name, entry.value);
            }
        }

        pub fn sendHandshakeHeadComplete(self: *Self) WriterError!void {
            return self.handshake_client.writeHeadComplete();
        }

        pub const HandshakeError = ReaderError || HzzpClient.ReadError || error{ WrongResponse, InvalidConnectionHeader, FailedChallenge, ConnectionClosed };
        pub fn waitForHandshake(self: *Self) HandshakeError!void {
            var got_upgrade_header: bool = false;
            var got_accept_header: bool = false;

            while (try self.handshake_client.readEvent()) |event| {
                switch (event) {
                    .status => |etc| {
                        if (etc.code != 101) {
                            return error.WrongResponse;
                        }
                    },
                    .header => |etc| {
                        if (ascii.eqlIgnoreCase(etc.name, "connection")) {
                            got_upgrade_header = true;

                            if (!ascii.eqlIgnoreCase(etc.value, "upgrade")) {
                                return error.InvalidConnectionHeader;
                            }
                        } else if (ascii.eqlIgnoreCase(etc.name, "sec-websocket-accept")) {
                            got_accept_header = true;

                            if (!checkHandshakeKey(&self.handshake_key, etc.value)) {
                                return error.FailedChallenge;
                            }
                        }
                    },
                    .end => break,
                    .invalid => return error.WrongResponse,
                    .closed => return error.ConnectionClosed,

                    else => {},
                }
            }

            if (!got_upgrade_header) {
                return error.InvalidConnectionHeader;
            } else if (!got_accept_header) {
                return error.FailedChallenge;
            }
        }

        pub fn writeMessageHeader(self: *Self, header: MessageHeader) WriterError!void {
            var bytes: [2]u8 = undefined;
            bytes[0] = @enumToInt(header.opcode);
            bytes[1] = 0;

            if (header.fin) bytes[0] |= 0x80;
            if (header.rsv1) bytes[0] |= 0x40;
            if (header.rsv2) bytes[0] |= 0x20;
            if (header.rsv3) bytes[0] |= 0x10;

            const mask = header.mask orelse self.prng.random.int(u32);
            bytes[1] |= 0x80;

            if (header.length < 126) {
                bytes[1] |= @truncate(u8, header.length);
                try self.writer.writeAll(&bytes);
            } else if (header.length < 0x10000) {
                bytes[1] |= 126;
                try self.writer.writeAll(&bytes);

                var len: [2]u8 = undefined;
                mem.writeIntBig(u16, &len, @truncate(u16, header.length));

                try self.writer.writeAll(&len);
            } else {
                bytes[1] |= 127;
                try self.writer.writeAll(&bytes);

                var len: [8]u8 = undefined;
                mem.writeIntBig(u64, &len, header.length);

                try self.writer.writeAll(&len);
            }

            var mask_bytes: [4]u8 = undefined;
            mem.writeIntLittle(u32, &mask_bytes, mask);

            try self.writer.writeAll(&mask_bytes);

            self.current_mask = mask;
            self.mask_index = 0;
        }

        pub fn maskPayload(self: *Self, payload: []const u8, buffer: []u8) void {
            if (self.current_mask) |mask| {
                assert(buffer.len >= payload.len);

                for (payload) |c, i| {
                    buffer[i] = c ^ extractMaskByte(mask, i + self.mask_index);
                }

                self.mask_index += payload.len;
            }
        }

        pub fn writeUnmaskedPayload(self: *Self, payload: []const u8) WriterError!void {
            try self.writer.writeAll(payload);
        }

        pub fn writeMessagePayload(self: *Self, payload: []const u8) WriterError!void {
            const mask = self.current_mask.?;
            for (payload) |c, i| {
                try self.writer.writeByte(c ^ extractMaskByte(mask, i + self.mask_index));
            }

            self.mask_index += payload.len;
        }

        pub fn readEvent(self: *Self) ReaderError!?ClientEvent {
            switch (self.state) {
                .header => {
                    const read_head_len = try self.reader.readAll(self.read_buffer[0..2]);
                    if (read_head_len != 2) return ClientEvent.closed;

                    const fin = self.read_buffer[0] & 0x80 == 0x80;
                    const rsv1 = self.read_buffer[0] & 0x40 == 0x40;
                    const rsv2 = self.read_buffer[0] & 0x20 == 0x20;
                    const rsv3 = self.read_buffer[0] & 0x10 == 0x10;
                    const opcode = @truncate(u4, self.read_buffer[0]);

                    const masked = self.read_buffer[1] & 0x80 == 0x80;
                    const check_len = @truncate(u7, self.read_buffer[1]);
                    var len: u64 = check_len;

                    var mask_index: u4 = 2;

                    if (check_len == 127) {
                        const read_len_len = try self.reader.readAll(self.read_buffer[2..10]);
                        if (read_len_len != 8) return ClientEvent.closed;

                        mask_index = 10;
                        len = mem.readIntBig(u64, self.read_buffer[2..10]);

                        self.chunk_need = len;
                        self.chunk_read = 0;
                    } else if (check_len == 126) {
                        const read_len_len = try self.reader.readAll(self.read_buffer[2..4]);
                        if (read_len_len != 2) return ClientEvent.closed;

                        mask_index = 4;
                        len = mem.readIntBig(u16, self.read_buffer[2..4]);

                        self.chunk_need = len;
                        self.chunk_read = 0;
                    } else {
                        self.chunk_need = check_len;
                        self.chunk_read = 0;
                    }

                    if (masked) {
                        const read_mask_len = try self.reader.readAll(self.read_buffer[mask_index .. mask_index + 4]);
                        if (read_mask_len != 4) return ClientEvent.closed;

                        self.chunk_mask = mem.readIntSliceBig(u32, self.read_buffer[mask_index .. mask_index + 4]);
                    } else {
                        self.chunk_mask = null;
                    }

                    self.state = .chunk;

                    return ClientEvent{
                        .header = .{
                            .fin = fin,
                            .rsv1 = rsv1,
                            .rsv2 = rsv2,
                            .rsv3 = rsv3,
                            .opcode = @intToEnum(Opcode, opcode),
                            .length = len,
                            .mask = self.chunk_mask,
                        },
                    };
                },
                .chunk => {
                    const left = self.chunk_need - self.chunk_read;

                    if (left <= self.read_buffer.len) {
                        const read_len = try self.reader.readAll(self.read_buffer[0..left]);
                        if (read_len != left) return ClientEvent.closed;

                        if (self.chunk_mask) |mask| {
                            for (self.read_buffer[0..read_len]) |*c, i| {
                                c.* = c.* ^ extractMaskByte(mask, i + self.chunk_read);
                            }
                        }

                        self.state = .header;
                        return ClientEvent{
                            .chunk = .{
                                .data = self.read_buffer[0..read_len],
                                .final = true,
                            },
                        };
                    } else {
                        const read_len = try self.reader.read(self.read_buffer);
                        if (read_len == 0) return ClientEvent.closed;

                        if (self.chunk_mask) |mask| {
                            for (self.read_buffer[0..read_len]) |*c, i| {
                                c.* = c.* ^ extractMaskByte(mask, i + self.chunk_read);
                            }
                        }

                        self.chunk_read += read_len;
                        return ClientEvent{
                            .chunk = .{
                                .data = self.read_buffer[0..read_len],
                            },
                        };
                    }
                },
            }
        }
    };
}

const testing = std.testing;
const io = std.io;

test "decodes a simple message" {
    var read_buffer: [32]u8 = undefined;
    var the_void: [1024]u8 = undefined;
    var response = [_]u8{
        0x82, 0x0d, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f,
        0x72, 0x6c, 0x64, 0x21,
    };

    var reader = io.fixedBufferStream(&response).reader();
    var writer = io.fixedBufferStream(&the_void).writer();

    var client = create(&read_buffer, reader, writer);
    client.handshaken = true;

    try client.writeMessageHeader(.{
        .opcode = Opcode.Binary,
        .length = 9,
    });

    try client.writeUnmaskedPayload("aaabbbccc");

    var header = (try client.readEvent()).?;
    testing.expect(header == .header);
    testing.expect(header.header.fin == true);
    testing.expect(header.header.rsv1 == false);
    testing.expect(header.header.rsv2 == false);
    testing.expect(header.header.rsv3 == false);
    testing.expect(header.header.opcode == Opcode.Binary);
    testing.expect(header.header.length == 13);
    testing.expect(header.header.mask == null);

    var payload = (try client.readEvent()).?;
    testing.expect(payload == .chunk);
    testing.expect(payload.chunk.final == true);
    testing.expect(mem.eql(u8, payload.chunk.data, "Hello, World!"));
}

test "decodes a masked message" {
    var read_buffer: [32]u8 = undefined;
    var the_void: [1024]u8 = undefined;
    var response = [_]u8{
        0x82, 0x8d, 0x12, 0x34, 0x56, 0x78, 0x30, 0x33, 0x58, 0x7e, 0x17,
        0x7a, 0x14, 0x45, 0x17, 0x24, 0x58, 0x76, 0x59,
    };

    var reader = io.fixedBufferStream(&response).reader();
    var writer = io.fixedBufferStream(&the_void).writer();

    var client = create(&read_buffer, reader, writer);
    client.handshaken = true;

    try client.writeMessageHeader(.{
        .opcode = Opcode.Binary,
        .length = 9,
    });

    try client.writeUnmaskedPayload("aaabbbccc");

    var header = (try client.readEvent()).?;
    testing.expect(header == .header);
    testing.expect(header.header.fin == true);
    testing.expect(header.header.rsv1 == false);
    testing.expect(header.header.rsv2 == false);
    testing.expect(header.header.rsv3 == false);
    testing.expect(header.header.opcode == Opcode.Binary);
    testing.expect(header.header.length == 13);
    testing.expect(header.header.mask.? == 0x12345678);

    var payload = (try client.readEvent()).?;
    testing.expect(payload == .chunk);
    testing.expect(payload.chunk.final == true);
    testing.expect(mem.eql(u8, payload.chunk.data, "Hello, World!"));
}

test "attempt echo on echo.websocket.org" {
    if (std.builtin.os.tag == .windows) return error.SkipZigTest;

    var socket = try std.net.tcpConnectToHost(testing.allocator, "echo.websocket.org", 80);
    defer socket.close();

    var buffer: [4096]u8 = undefined;

    var client = create(&buffer, socket.reader(), socket.writer());

    try client.sendHandshakeHead("/");
    try client.sendHandshakeHeaderValue("Host", "echo.websocket.org");
    try client.sendHandshakeHeadComplete();

    try client.waitForHandshake();

    try client.writeMessageHeader(.{
        .opcode = Opcode.Binary,
        .length = 4,
    });

    try client.writeMessagePayload("test");

    var header = (try client.readEvent()).?;
    testing.expect(header == .header);
    testing.expect(header.header.fin == true);
    testing.expect(header.header.rsv1 == false);
    testing.expect(header.header.rsv2 == false);
    testing.expect(header.header.rsv3 == false);
    testing.expect(header.header.opcode == Opcode.Binary);
    testing.expect(header.header.length == 4);
    testing.expect(header.header.mask == null);

    var payload = (try client.readEvent()).?;
    testing.expect(payload == .chunk);
    testing.expect(payload.chunk.final == true);
    testing.expect(mem.eql(u8, payload.chunk.data, "test"));
}
