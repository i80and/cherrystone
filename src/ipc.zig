const Message = struct {
    type: MessageType,
    data: []const u8,
};

const MessageType = enum {
    REQUEST,
    RESPONSE,
};
