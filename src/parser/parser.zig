const std = @import("std");

pub const client = @import("client.zig");

comptime {
    std.testing.refAllDecls(@This());
}
