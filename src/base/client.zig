const std = @import("std");

const wz = @import("../main.zig");
const parser = @import("../main.zig").parser.message;

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

pub fn HandshakeClient(comptime Reader: type, comptime Writer: type) type {
    const HttpClient = hzzp.base.client.BaseClient(Reader, Writer);
    const WzClient = BaseClient(Reader, Writer);

    return struct {
        const Self = @This();

        prng: std.rand.Random,
        client: HttpClient,
        handshake_key: [handshake_key_length_b64]u8 = undefined,

        got_upgrade_header: bool = false,
        got_accept_header: bool = false,
        handshaken: bool = false,

        pub fn init(buffer: []u8, input: Reader, output: Writer, prng: std.rand.Random) Self {
            return .{
                .prng = prng,
                .client = HttpClient.init(buffer, input, output),
            };
        }

        pub fn generateKey(self: *Self) void {
            var raw_key: [handshake_key_length]u8 = undefined;
            self.prng.bytes(&raw_key);

            _ = base64.standard.Encoder.encode(&self.handshake_key, &raw_key);
        }

        fn addRequiredHeaders(self: *Self) Writer.Error!void {
            self.generateKey();

            try self.client.writeHeaderValue("Connection", "Upgrade");
            try self.client.writeHeaderValue("Upgrade", "websocket");
            try self.client.writeHeaderValue("Sec-WebSocket-Version", "13");
            try self.client.writeHeaderValue("Sec-WebSocket-Key", &self.handshake_key);
        }

        pub fn writeStatusLine(self: *Self, path: []const u8) Writer.Error!void {
            try self.client.writeStatusLine("GET", path);
        }

        pub fn writeStatusLineParts(self: *Self, path: []const u8, query: ?[]const u8, fragment: ?[]const u8) Writer.Error!void {
            try self.client.writeStatusLineParts("GET", path, query, fragment);
        }

        pub fn writeHeaderValue(self: *Self, name: []const u8, value: []const u8) Writer.Error!void {
            return self.client.writeHeaderValue(name, value);
        }

        pub fn writeHeaderFormat(self: *Self, name: []const u8, comptime format: []const u8, args: anytype) Writer.Error!void {
            return self.client.writeHeaderFormat(name, format, args);
        }

        pub fn writeHeader(self: *Self, header: hzzp.Header) Writer.Error!void {
            return self.client.writeHeader(header);
        }

        pub fn writeHeaders(self: *Self, headers: hzzp.HeadersSlice) Writer.Error!void {
            return self.client.writeHeaders(headers);
        }

        pub fn finishHeaders(self: *Self) Writer.Error!void {
            try self.addRequiredHeaders();

            try self.client.finishHeaders();
        }

        pub const HandshakeError = error{ WrongResponse, InvalidConnectionHeader, FailedChallenge } || HttpClient.NextError;
        pub fn wait(self: *Self) HandshakeError!bool {
            while (try self.client.next()) |event| {
                switch (event) {
                    .status => |status| {
                        if (status.code != 101) return error.WrongResponse;
                    },
                    .header => |header| {
                        if (ascii.eqlIgnoreCase(header.name, "connection")) {
                            self.got_upgrade_header = true;

                            if (!ascii.eqlIgnoreCase(header.value, "upgrade")) {
                                return error.InvalidConnectionHeader;
                            }
                        } else if (ascii.eqlIgnoreCase(header.name, "sec-websocket-accept")) {
                            self.got_accept_header = true;

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

            self.handshaken = self.got_upgrade_header and self.got_accept_header;
            return self.handshaken;
        }

        pub fn socket(self: Self) WzClient {
            assert(self.handshaken);

            return WzClient.init(self.client.read_buffer, self.client.parser.reader, self.client.writer, self.prng);
        }
    };
}

pub fn BaseClient(comptime Reader: type, comptime Writer: type) type {
    const ParserType = parser.MessageParser(Reader);

    return struct {
        const Self = @This();

        read_buffer: []u8,
        parser: ParserType,
        writer: Writer,

        current_mask: [4]u8 = std.mem.zeroes([4]u8),
        mask_index: usize = 0,

        payload_size: usize = 0,
        payload_index: usize = 0,

        prng: std.rand.Random,

        // Whether a reader is currently using the read_buffer. if true, parser.next should NOT be called since the
        // reader expects all of the data.
        self_contained: bool = false,

        pub const handshake = HandshakeClient(Reader, Writer).init;

        pub fn init(buffer: []u8, input: Reader, output: Writer, prng: std.rand.Random) Self {
            return .{
                .parser = ParserType.init(buffer, input),
                .read_buffer = buffer,
                .writer = output,
                .prng = prng,
            };
        }

        pub const WriteHeaderError = error{MissingMask} || Writer.Error;
        pub fn writeHeader(self: *Self, header: wz.MessageHeader) WriteHeaderError!void {
            var bytes: [14]u8 = undefined;
            var len: usize = 2;

            bytes[0] = @enumToInt(header.opcode);

            if (header.fin) bytes[0] |= 0x80;
            if (header.rsv1) bytes[0] |= 0x40;
            if (header.rsv2) bytes[0] |= 0x20;
            if (header.rsv3) bytes[0] |= 0x10;

            // client messages MUST be masked.
            var mask: [4]u8 = undefined;
            if (header.mask) |m| {
                std.mem.copy(u8, &mask, &m);
            } else {
                self.prng.bytes(&mask);
            }

            bytes[1] = 0x80;

            if (header.length < 126) {
                bytes[1] |= @truncate(u8, header.length);
            } else if (header.length < 0x10000) {
                bytes[1] |= 126;

                mem.writeIntBig(u16, bytes[2..4], @truncate(u16, header.length));
                len += 2;
            } else {
                bytes[1] |= 127;

                mem.writeIntBig(u64, bytes[2..10], header.length);
                len += 8;
            }

            std.mem.copy(u8, bytes[len .. len + 4], &mask);
            len += 4;

            try self.writer.writeAll(bytes[0..len]);

            self.current_mask = mask;
            self.mask_index = 0;
        }

        pub fn writeChunkRaw(self: *Self, payload: []const u8) Writer.Error!void {
            try self.writer.writeAll(payload);
        }

        const mask_buffer_size = 1024;
        pub fn writeChunk(self: *Self, payload: []const u8) Writer.Error!void {
            var buffer: [mask_buffer_size]u8 = undefined;
            var index: usize = 0;

            for (payload) |c, i| {
                buffer[index] = c ^ self.current_mask[(i + self.mask_index) % 4];

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
        }

        pub fn next(self: *Self) ParserType.NextError!?parser.Event {
            assert(!self.self_contained);

            return self.parser.next();
        }

        pub const ReadNextError = ParserType.NextError;
        pub fn readNextChunk(self: *Self) ReadNextError!?parser.ChunkEvent {
            if (self.parser.state != .chunk) return null;
            assert(!self.self_contained);

            if (try self.parser.next()) |event| {
                switch (event) {
                    .chunk => |chunk| return chunk,
                    .header => unreachable,
                }
            }

            return null;
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

            const size = std.math.min(buffer.len, self.payload_size - self.payload_index);
            const end = self.payload_index + size;

            mem.copy(u8, buffer[0..size], self.read_buffer[self.payload_index..end]);
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

test "test server required" {
    const Reader = std.io.FixedBufferStream([]const u8).Reader;
    const Writer = std.io.FixedBufferStream([]u8).Writer;

    std.testing.refAllDecls(HandshakeClient(Reader, Writer));
    std.testing.refAllDecls(BaseClient(Reader, Writer));
}

test "example usage" {
    if (true) return error.SkipZigTest;

    var buffer: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    const reader = stream.reader();
    const writer = stream.writer();

    const Reader = @TypeOf(reader);
    const Writer = @TypeOf(writer);

    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var prng = std.rand.DefaultPrng.init(seed);

    var handshake = BaseClient(Reader, Writer).handshake(&buffer, reader, writer, prng.random());
    try handshake.writeStatusLine("/");
    try handshake.writeHeaderValue("Host", "echo.websocket.org");
    try handshake.finishHeaders();

    if (try handshake.wait()) {
        var client = handshake.socket();

        try client.writeHeader(.{
            .opcode = .binary,
            .length = 4,
        });

        try client.writeChunk("abcd");

        while (try client.next()) |event| {
            _ = event;
            // directly from the parser
        }
    }
}
