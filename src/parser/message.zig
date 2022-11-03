const std = @import("std");

const math = std.math;
const mem = std.mem;

const assert = std.debug.assert;

const wz = @import("../main.zig");
const util = @import("../util.zig");

pub const ChunkEvent = struct {
    data: []const u8,
    final: bool = false,
};

pub const Event = union(enum) {
    header: wz.MessageHeader,
    chunk: ChunkEvent,
};

pub fn create(buffer: []u8, reader: anytype) MessageParser(@TypeOf(reader)) {
    assert(buffer.len >= 14);

    return MessageParser(@TypeOf(reader)).init(buffer, reader);
}

pub fn MessageParser(comptime Reader: type) type {
    return struct {
        const Self = @This();

        read_buffer: []u8,

        chunk_read: usize = 0,
        mask_index: usize = 0,

        last_header: wz.MessageHeader = undefined,

        reader: Reader,

        state: util.ParserState = .header,

        pub fn init(buffer: []u8, reader: Reader) Self {
            return .{
                .read_buffer = buffer,
                .reader = reader,
            };
        }

        pub fn reset(self: *Self) void {
            self.chunk_read = 0;
            self.mask_index = 0;

            self.last_header = undefined;

            self.state = .header;
        }

        pub const NextError = error{EndOfStream} || Reader.Error;
        pub fn next(self: *Self) NextError!?Event {
            switch (self.state) {
                .header => {
                    const initial_read = try self.reader.readAll(self.read_buffer[0..2]);
                    if (initial_read != 2) return error.EndOfStream;

                    self.last_header.fin = self.read_buffer[0] & 0x80 == 0x80;
                    self.last_header.rsv1 = self.read_buffer[0] & 0x40 == 0x40;
                    self.last_header.rsv2 = self.read_buffer[0] & 0x20 == 0x20;
                    self.last_header.rsv3 = self.read_buffer[0] & 0x10 == 0x10;
                    self.last_header.opcode = @intToEnum(wz.Opcode, @truncate(u4, self.read_buffer[0]));

                    const masked = self.read_buffer[1] & 0x80 == 0x80;
                    const check_len = @truncate(u7, self.read_buffer[1]);

                    if (check_len == 127) {
                        const length_read = try self.reader.readAll(self.read_buffer[2..10]);
                        if (length_read != 8) return error.EndOfStream;

                        self.last_header.length = mem.readIntBig(u64, self.read_buffer[2..10]);
                    } else if (check_len == 126) {
                        const length_read = try self.reader.readAll(self.read_buffer[2..4]);
                        if (length_read != 2) return error.EndOfStream;

                        self.last_header.length = mem.readIntBig(u16, self.read_buffer[2..4]);
                    } else {
                        self.last_header.length = check_len;
                    }

                    if (masked) {
                        // This may leave a gap in the read buffer, but we have to have this space anyways.
                        // This is faster than keeping track of where we were writing into.
                        const mask_read = try self.reader.readAll(self.read_buffer[10..14]);
                        if (mask_read != 4) return error.EndOfStream;

                        self.last_header.mask = self.read_buffer[10..14].*;
                    } else {
                        self.last_header.mask = null;
                    }

                    self.chunk_read = 0;

                    self.state = .chunk;

                    return Event{
                        .header = self.last_header,
                    };
                },

                .chunk => {
                    const left = math.min(self.last_header.length - self.chunk_read, self.read_buffer.len);
                    const read = try self.reader.read(self.read_buffer[0..left]);

                    if (self.last_header.mask) |mask| {
                        for (self.read_buffer[0..read]) |*c, i| {
                            c.* = c.* ^ mask[(i + self.chunk_read) % 4];
                        }
                    }

                    self.chunk_read += read;

                    assert(self.chunk_read <= self.last_header.length);
                    if (self.chunk_read == self.last_header.length) {
                        self.state = .header;
                    }

                    return Event{
                        .chunk = .{
                            .data = self.read_buffer[0..read],
                            .final = self.chunk_read == self.last_header.length,
                        },
                    };
                },
            }
        }
    };
}

const testing = std.testing;
const io = std.io;

fn testNextField(parser: anytype, expected: ?Event) !void {
    const actual = try parser.next();

    try testing.expect(util.reworkedMetaEql(actual, expected));
}

test "parses simple unmasked payload" {
    var read_buffer: [32]u8 = undefined;
    var request = [_]u8{ 0x81, 0x04, 'a', 'b', 'c', 'd' };

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 4,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = "abcd",
            .final = true,
        },
    });
}

test "parses simple masked payload" {
    var read_buffer: [32]u8 = undefined;
    var request = [_]u8{ 0x81, 0x84, 0xa9, 0xb8, 0xc7, 0xd6, 'a' ^ 0xa9, 'b' ^ 0xb8, 'c' ^ 0xc7, 'd' ^ 0xd6 };

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 4,
            .mask = [4]u8{ 0xa9, 0xb8, 0xc7, 0xd6 },
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = "abcd",
            .final = true,
        },
    });
}

test "parses longer simple masked payload" {
    var read_buffer: [32]u8 = undefined;
    var request = [_]u8{ 0x81, 0x90, 0xa9, 0xb8, 0xc7, 0xd6 } ++ [_]u8{ 'a' ^ 0xa9, 'b' ^ 0xb8, 'c' ^ 0xc7, 'd' ^ 0xd6 } ** (0x10 / 4);

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 0x10,
            .mask = [4]u8{ 0xa9, 0xb8, 0xc7, 0xd6 },
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = &[_]u8{ 'a', 'b', 'c', 'd' } ** (0x10 / 4),
            .final = true,
        },
    });
}

test "parses more than one simple unmasked payload" {
    var read_buffer: [32]u8 = undefined;
    var request = [_]u8{ 0x81, 0x04, 'a', 'b', 'c', 'd', 0x81, 0x04, 'a', 'b', 'c', 'd', 0x81, 0x04, 'a', 'b', 'c', 'd' };

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 4,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = "abcd",
            .final = true,
        },
    });

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 4,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = "abcd",
            .final = true,
        },
    });

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 4,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = "abcd",
            .final = true,
        },
    });
}

test "parses simple unmasked medium payload" {
    var read_buffer: [512]u8 = undefined;
    var request = [_]u8{ 0x81, 0x07e, 0x01, 0x00 } ++ [_]u8{ 'a', 'b', 'c', 'd' } ** (0x100 / 4);

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 0x100,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = &[_]u8{ 'a', 'b', 'c', 'd' } ** (0x100 / 4),
            .final = true,
        },
    });
}

test "parses chunks simple unmasked medium payload" {
    var read_buffer: [128]u8 = undefined;
    var request = [_]u8{ 0x81, 0x07e, 0x01, 0x00 } ++ [_]u8{ 'a', 'b', 'c', 'd' } ** (0x100 / 4);

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 0x100,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = &[_]u8{ 'a', 'b', 'c', 'd' } ** (128 / 4),
            .final = false,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = &[_]u8{ 'a', 'b', 'c', 'd' } ** (128 / 4),
            .final = true,
        },
    });
}

test "parses simple unmasked large payload" {
    var read_buffer: [0x10000]u8 = undefined;
    var request = [_]u8{ 0x81, 0x07f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 } ++ [_]u8{ 'a', 'b', 'c', 'd' } ** (0x10000 / 4);

    var fbs = io.fixedBufferStream(&request);
    var reader = fbs.reader();
    var parser = create(&read_buffer, reader);

    try testNextField(&parser, .{
        .header = .{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .length = 0x10000,
            .mask = null,
        },
    });

    try testNextField(&parser, .{
        .chunk = .{
            .data = &[_]u8{ 'a', 'b', 'c', 'd' } ** (0x10000 / 4),
            .final = true,
        },
    });
}
