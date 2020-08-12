
pub const ParserState = enum {
    header,
    chunk,
};

pub const MessageHeader = struct {
    fin: bool = true,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: u4,
    length: u64,
    mask: ?u32 = null,
};

pub const Chunk = struct {
    data: []const u8,
    final: bool = false,
};

pub const Invalid = struct {
    buffer: []const u8,
    message: []const u8,
    state: ParserState,
};

pub const ClientEvent = union(enum) {
    header: MessageHeader,
    chunk: Chunk,
    end: void,
    invalid: Invalid,
    closed: void,
};