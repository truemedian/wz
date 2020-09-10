pub const hzzp = @import("hzzp").base;

pub const ParserState = enum {
    header,
    chunk,
};

pub const MessageHeader = struct {
    fin: bool = true,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: Opcode,
    length: u64,
    mask: ?u32 = null,
};

pub const Opcode = enum(u4) {
    Continuation,
    Text,
    Binary,
    Close = 0x08,
    Ping,
    Pong,
};

pub const ChunkEvent = struct {
    data: []const u8,
    final: bool = false,
};

pub const InvalidEvent = struct {
    buffer: []const u8,
    message: []const u8,
    state: ParserState,
};

pub const ClientEvent = union(enum) {
    header: MessageHeader,
    chunk: ChunkEvent,
    end: void,
    invalid: InvalidEvent,
    closed: void,
};
