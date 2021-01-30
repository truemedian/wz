const std = @import("std");

usingnamespace @import("common.zig");

const base64 = std.base64;
const ascii = std.ascii;
const math = std.math;
const time = std.time;
const rand = std.rand;
const mem = std.mem;

const assert = std.debug.assert;

pub fn extractMaskByte(mask: u32, index: usize) u8 {
    return @truncate(u8, mask >> @truncate(u5, (index % 4) * 8));
}

pub fn create(buffer: []u8, reader: anytype) Client(@TypeOf(reader)) {
    assert(buffer.len >= 16);

    return ClientParser(@TypeOf(reader)).init(buffer, reader);
}

pub fn ClientParser(comptime Reader: type) type {
    return struct {
        const Self = @This();

        read_buffer: []u8,

        reader: Reader,

        current_mask: ?u32 = null,
        mask_index: usize = 0,

        chunk_need: usize = 0,
        chunk_read: usize = 0,
        chunk_mask: ?u32 = null,

        state: ParserState = .header,

        pub fn init(buffer: []u8, reader: Reader) Self {
            return .{
                .read_buffer = buffer,
                .reader = reader,
            };
        }

        pub fn reset(self: *Self) void {
            self.current_mask = null;
            self.mask_index = 0;

            self.chunk_need = 0;
            self.chunk_read = 0;
            self.chunk_mask = null;

            self.state = .header;
        }

        pub const NextError = error{EndOfStream} || Reader.Error;
        pub fn next(self: *Self) NextError!?Event {
            switch (self.state) {
                .header => {
                    const read_head_len = try self.reader.readAll(self.read_buffer[0..2]);
                    if (read_head_len != 2) return error.EndOfStream;

                    const fin = self.read_buffer[0] & 0x80 == 0x80;
                    const rsv1 = self.read_buffer[0] & 0x40 == 0x40;
                    const rsv2 = self.read_buffer[0] & 0x20 == 0x20;
                    const rsv3 = self.read_buffer[0] & 0x10 == 0x10;
                    const opcode = @truncate(u4, self.read_buffer[0]);

                    const masked = self.read_buffer[1] & 0x80 == 0x80;
                    const check_len = @truncate(u7, self.read_buffer[1]);
                    var len: u64 = check_len;

                    var mask_index: u4 = 2;

                    self.chunk_read = 0;
                    if (check_len == 127) {
                        const read_len_len = try self.reader.readAll(self.read_buffer[2..10]);
                        if (read_len_len != 8) return error.EndOfStream;

                        mask_index = 10;
                        len = mem.readIntBig(u64, self.read_buffer[2..10]);

                        self.chunk_need = len;
                    } else if (check_len == 126) {
                        const read_len_len = try self.reader.readAll(self.read_buffer[2..4]);
                        if (read_len_len != 2) return error.EndOfStream;

                        mask_index = 4;
                        len = mem.readIntBig(u16, self.read_buffer[2..4]);

                        self.chunk_need = len;
                    } else {
                        self.chunk_need = check_len;
                    }

                    if (masked) {
                        const read_mask_len = try self.reader.readAll(self.read_buffer[mask_index .. mask_index + 4]);
                        if (read_mask_len != 4) return error.EndOfStream;

                        self.chunk_mask = mem.readIntSliceBig(u32, self.read_buffer[mask_index .. mask_index + 4]);
                    } else {
                        self.chunk_mask = null;
                    }

                    self.state = .chunk;

                    return Event{
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
                    const left = math.min(self.chunk_need - self.chunk_read, self.read_buffer.len);
                    const read = try self.reader.read(self.read_buffer[0..left]);

                    self.chunk_read += read;

                    if (self.chunk_mask) |mask| {
                        for (self.read_buffer[0..read]) |*c, i| {
                            c.* = c.* ^ extractMaskByte(mask, i + self.chunk_read);
                        }
                    }

                    assert(self.chunk_read <= self.chunk_need);
                    if (self.chunk_read == self.chunk_need) {
                        self.state = .header;
                    }

                    return Event{
                        .chunk = .{
                            .data = self.read_buffer[0..read],
                            .final = self.chunk_read == self.chunk_need,
                        },
                    };
                },
            }
        }
    };
}
