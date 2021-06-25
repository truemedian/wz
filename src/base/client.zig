const std = @import("std");

usingnamespace @import("common.zig");

const parser = @import("../main.zig").parser.client;

const hzzp = @import("hzzp");

const base64 = std.base64;
const ascii = std.ascii;
const math = std.math;
const rand = std.rand;
const time = std.time;
const mem = std.mem;

const Sha1 = std.crypto.hash.Sha1;

const assert = std.debug.assert;

pub fn create(buffer: []u8, reader: anytype, writer: anytype) BaseClient(@TypeOf(reader), @TypeOf(writer)) {
    assert(buffer.len >= 16);

    return BaseClient(@TypeOf(reader), @TypeOf(writer)).init(buffer, reader, writer);
}

pub const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const handshake_key_length = 16;
pub const handshake_key_length_b64 = base64.standard.Encoder.calcSize(handshake_key_length);
pub const encoded_key_length_b64 = base64.standard.Encoder.calcSize(Sha1.digest_length);

fn checkHandshakeKey(original: []const u8, received: []const u8) bool {
    var hash = Sha1.init(.{});
    hash.update(original);
    hash.update(websocket_guid);

    var hashed_key: [Sha1.digest_length]u8 = undefined;
    hash.final(&hashed_key);

    var encoded: [encoded_key_length_b64]u8 = undefined;
    _ = base64.standard.Encoder.encode(&encoded, &hashed_key);

    return mem.eql(u8, &encoded, received);
}

pub fn BaseClient(comptime Reader: type, comptime Writer: type) type {
    const ParserType = parser.ClientParser(Reader);
    const HttpClient = hzzp.base.client.BaseClient(Reader, Writer);

    return struct {
        const Self = @This();

        prng: rand.DefaultPrng,
        handshake_client: HttpClient,
        handshake_key: [handshake_key_length_b64]u8 = undefined,

        read_buffer: []u8,
        parser: ParserType,
        writer: Writer,

        handshaken: bool = false,

        current_mask: ?u32 = null,
        mask_index: usize = 0,

        payload_size: usize = 0,
        payload_index: usize = 0,

        // Whether a reader is currently using the read_buffer. if true, parser.next should NOT be called since the
        // reader expects all of the data.
        self_contained: bool = false,

        pub fn init(buffer: []u8, input: Reader, output: Writer) Self {
            const rand_seed = @truncate(u64, @bitCast(u128, time.nanoTimestamp()));

            return .{
                .prng = rand.DefaultPrng.init(rand_seed),
                .handshake_client = HttpClient.init(buffer, input, output),
                .parser = ParserType.init(buffer, input),
                .read_buffer = buffer,
                .writer = output,
            };
        }

        pub fn handshakeStart(self: *Self, path: []const u8) Writer.Error!void {
            var raw_key: [handshake_key_length]u8 = undefined;
            self.prng.random.bytes(&raw_key);

            _ = base64.standard_encoder.encode(&self.handshake_key, &raw_key);

            try self.handshake_client.writeStatusLine("GET", path);
            try self.handshake_client.writeHeaderValue("Connection", "Upgrade");
            try self.handshake_client.writeHeaderValue("Upgrade", "websocket");
            try self.handshake_client.writeHeaderValue("Sec-WebSocket-Version", "13");
            try self.handshake_client.writeHeaderValue("Sec-WebSocket-Key", &self.handshake_key);
        }

        pub fn handshakeAddHeaderValue(self: *Self, name: []const u8, value: []const u8) Writer.Error!void {
            return self.handshake_client.writeHeaderValue(name, value);
        }

        pub fn handshakeAddHeaderValueFormat(self: *Self, name: []const u8, comptime format: []const u8, args: anytype) Writer.Error!void {
            return self.handshake_client.writeHeaderFormat(name, format, args);
        }

        pub const HandshakeError = error{ WrongResponse, InvalidConnectionHeader, FailedChallenge } || HttpClient.NextError || Writer.Error;
        pub fn handshakeFinish(self: *Self) HandshakeError!void {
            try self.handshake_client.finishHeaders();

            var got_upgrade_header: bool = false;
            var got_accept_header: bool = false;

            while (try self.handshake_client.next()) |event| {
                switch (event) {
                    .status => |status| {
                        if (status.code != 101) return error.WrongResponse;
                    },
                    .header => |header| {
                        if (ascii.eqlIgnoreCase(header.name, "connection")) {
                            got_upgrade_header = true;

                            if (!ascii.eqlIgnoreCase(header.value, "upgrade")) {
                                return error.InvalidConnectionHeader;
                            }
                        } else if (ascii.eqlIgnoreCase(header.name, "sec-websocket-accept")) {
                            got_accept_header = true;

                            if (!checkHandshakeKey(&self.handshake_key, header.value)) {
                                return error.FailedChallenge;
                            }
                        }
                    },
                    .head_done => break,
                    .payload => unreachable,

                    .skip => {},
                    .end => break,
                }
            }

            self.handshaken = true;
        }

        pub fn writeHeader(self: *Self, header: MessageHeader) Writer.Error!void {
            assert(self.handshaken);

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

        pub fn writeChunkRaw(self: *Self, payload: []const u8) Writer.Error!void {
            try self.writer.writeAll(payload);
        }

        const mask_buffer_size = 1024;
        pub fn writeChunk(self: *Self, payload: []const u8) Writer.Error!void {
            if (self.current_mask) |mask| {
                var buffer: [mask_buffer_size]u8 = undefined;
                var index: usize = 0;

                for (payload) |c, i| {
                    buffer[index] = c ^ parser.extractMaskByte(mask, i + self.mask_index);

                    index += 1;
                    if (index == mask_buffer_size) {
                        try self.writer.writeAll(&buffer);

                        index = 0;
                    }
                }

                if (index > 0) {
                    try self.writer.writeAll(buffer[0..index]);
                }

                self.mask_index += payload.len;
            } else unreachable;
        }

        pub fn next(self: *Self) ParserType.NextError!?Event {
            assert(self.handshaken);
            assert(!self.self_contained);

            return self.parser.next();
        }

        pub const ReadNextError = ParserType.NextError;
        pub fn readNextChunk(self: *Self) ReadNextError!?ChunkEvent {
            if (self.parser.state != .chunk) return null;
            assert(self.handshaken);
            assert(!self.self_contained);

            if (try self.parser.next()) |event| {
                switch (event) {
                    .chunk => |chunk| return chunk,
                    .header => unreachable,
                }
            }
        }

        pub fn flushReader(self: *Self) ReadNextError!void {
            var buffer: [256]u8 = undefined;
            while (self.self_contained) {
                _ = try self.readNextChunkBuffer(&buffer);
            }
        }

        pub fn readNextChunkBuffer(self: *Self, buffer: []u8) ReadNextError!usize {
            if (self.payload_index >= self.payload_size) {
                if (self.parser.state != .chunk) {
                    self.self_contained = false;
                    return 0;
                }

                self.self_contained = true;

                if (try self.parser.next()) |event| {
                    switch (event) {
                        .chunk => |chunk| {
                            self.payload_index = 0;
                            self.payload_size = chunk.data.len;
                        },

                        .header => unreachable,
                    }
                } else unreachable;
            }

            const start = self.payload_index;
            const size = std.math.min(buffer.len, self.payload_size - start);
            const end = start + size;

            mem.copy(u8, buffer[0..size], self.read_buffer[start..end]);
            self.payload_index = end;

            return size;
        }

        pub const PayloadReader = std.io.Reader(*Self, ReadNextError, readNextChunkBuffer);

        pub fn reader(self: *Self) PayloadReader {
            assert(self.parser.state == .chunk);

            return .{ .context = self };
        }
    };
}

const testing = std.testing;

test "attempt echo on echo.websocket.org" {
    if (std.builtin.os.tag == .windows) return error.SkipZigTest;

    var socket = try std.net.tcpConnectToHost(testing.allocator, "echo.websocket.org", 80);
    defer socket.close();

    var buffer: [4096]u8 = undefined;

    var client = create(&buffer, socket.reader(), socket.writer());

    try client.handshakeStart("/");
    try client.handshakeAddHeaderValue("Host", "echo.websocket.org");

    try client.handshakeFinish();

    try client.writeHeader(.{
        .opcode = .Binary,
        .length = 4,
    });

    try client.writeChunk("test");

    var header = (try client.next()).?;
    try testing.expect(header == .header);
    try testing.expect(header.header.fin == true);
    try testing.expect(header.header.rsv1 == false);
    try testing.expect(header.header.rsv2 == false);
    try testing.expect(header.header.rsv3 == false);
    try testing.expect(header.header.opcode == .Binary);
    try testing.expect(header.header.length == 4);
    try testing.expect(header.header.mask == null);

    var payload = (try client.next()).?;
    try testing.expect(payload == .chunk);
    try testing.expect(payload.chunk.final == true);
    try testing.expect(mem.eql(u8, payload.chunk.data, "test"));
}

test "reader() and flushReader()" {
    if (std.builtin.os.tag == .windows) return error.SkipZigTest;

    var socket = try std.net.tcpConnectToHost(testing.allocator, "echo.websocket.org", 80);
    defer socket.close();

    const payload = "0123456789ABCDEF" ** 32;
    // Intentionally smaller buffer to require multiple chunks
    var buffer: [payload.len / 2]u8 = undefined;

    var client = create(&buffer, socket.reader(), socket.writer());

    try client.handshakeStart("/");
    try client.handshakeAddHeaderValue("Host", "echo.websocket.org");

    try client.handshakeFinish();

    try client.writeHeader(.{
        .opcode = .Binary,
        .length = payload.len,
    });

    try client.writeChunk(payload);

    var header = (try client.next()).?;
    try testing.expect(header == .header);
    try testing.expect(header.header.fin == true);
    try testing.expect(header.header.rsv1 == false);
    try testing.expect(header.header.rsv2 == false);
    try testing.expect(header.header.rsv3 == false);
    try testing.expect(header.header.opcode == .Binary);
    try testing.expect(header.header.length == payload.len);
    try testing.expect(header.header.mask == null);

    try testing.expect(client.parser.state == .chunk);

    const reader = client.reader();
    try testing.expect((try reader.readByte()) == '0');
    try testing.expect((try reader.readByte()) == '1');
    try testing.expect((try reader.readByte()) == '2');
    try client.flushReader();
    try testing.expectError(error.EndOfStream, reader.readByte());
    try testing.expect(client.parser.state != .chunk);

    // Allow multiple flushes to make cleanup easier
    try client.flushReader();
}
