pub const MessageHeader = struct {
    fin: bool = true,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: Opcode,
    length: u64,
    mask: ?[4]u8 = null,
};

pub const Opcode = enum(u4) {
    continuation = 0x00,
    text = 0x01,
    binary = 0x02,
    close = 0x08,
    ping = 0x09,
    pong = 0x0a,
    _,
};
