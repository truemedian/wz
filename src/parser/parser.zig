const std = @import("std");

pub const message = @import("message.zig");

comptime {
    std.testing.refAllDecls(@This());
}
