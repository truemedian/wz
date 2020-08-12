const std = @import("std");

pub usingnamespace @import("common.zig");

pub const Client = @import("client.zig");

test "refAllDecls" {
    std.meta.refAllDecls(@This());
}
