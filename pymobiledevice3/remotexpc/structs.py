from typing import Mapping

from construct import Aligned, Array, Byte, Bytes, Const, CString, Default, Double, Enum, FixedSized, FlagsEnum, Hex, \
    If, Int32ul, Int64sl, Int64ul, LazyBound, Prefixed, Struct, Switch, setGlobalPrintFullStrings, this

XpcMessageType = Enum(Hex(Int32ul),
                      NULL=0x00001000,
                      BOOL=0x00002000,
                      INT64=0x00003000,
                      UINT64=0x00004000,
                      DOUBLE=0x00005000,
                      POINTER=0x00006000,
                      DATE=0x00007000,
                      DATA=0x00008000,
                      STRING=0x00009000,
                      UUID=0x0000a000,
                      FD=0x0000b000,
                      SHMEM=0x0000c000,
                      MACH_SEND=0x0000d000,
                      ARRAY=0x0000e000,
                      DICTIONARY=0x0000f000,
                      ERROR=0x00010000,
                      CONNECTION=0x00011000,
                      ENDPOINT=0x00012000,
                      SERIALIZER=0x00013000,
                      PIPE=0x00014000,
                      MACH_RECV=0x00015000,
                      BUNDLE=0x00016000,
                      SERVICE=0x00017000,
                      SERVICE_INSTANCE=0x00018000,
                      ACTIVITY=0x00019000,
                      FILE_TRANSFER=0x0001a000,
                      )

setGlobalPrintFullStrings(True)
XpcFlags = FlagsEnum(Hex(Int32ul),
                     ALWAYS_SET=0x00000001,
                     DATA_PRESENT=0x00000100,
                     HEARTBEAT_REQUEST=0x00010000,
                     HEARTBEAT_RESPONSE=0x00020000,
                     FILE_TX_STREAM_REQUEST=0x00100000,
                     FILE_TX_STREAM_RESPONSE=0x00200000,
                     INIT_HANDSHAKE=0x00400000,
                     )

AlignedString = Aligned(4, CString('utf8'))
XpcNull = None
XpcBool = Int32ul
XpcInt64 = Int64sl
XpcUInt64 = Int64ul
XpcDouble = Double
XpcPointer = None
XpcDate = Int64ul
XpcData = Prefixed(Int32ul, Byte)
XpcString = Aligned(4, Prefixed(Int32ul, CString('utf8')))
XpcUuid = Bytes(16)
XpcFd = Int32ul
XpcShmem = Struct('length' / Int32ul, Int32ul)
XpcArray = Prefixed(Int32ul, LazyBound(lambda: XpcObject))

XpcDictionaryEntry = Struct(
    'key' / AlignedString,
    'value' / LazyBound(lambda: XpcObject),
)

XpcDictionary = Struct(
    'size' / Hex(Int32ul),
    'count' / Hex(Int32ul),
    'entries' / If(this.count > 0, FixedSized(this.size - 4, Array(this.count, XpcDictionaryEntry))),
)

XpcObject = Struct(
    'type' / XpcMessageType,
    'data' / Switch(this.type, {
        XpcMessageType.DICTIONARY: XpcDictionary,
        XpcMessageType.STRING: XpcString,
        XpcMessageType.INT64: XpcInt64,
        XpcMessageType.UINT64: XpcUInt64,
        XpcMessageType.DOUBLE: XpcDouble,
        XpcMessageType.BOOL: XpcBool,
        XpcMessageType.NULL: XpcNull,
        XpcMessageType.UUID: XpcUuid,
        XpcMessageType.POINTER: XpcPointer,
        XpcMessageType.DATE: XpcDate,
        XpcMessageType.DATA: XpcData,
        XpcMessageType.FD: XpcFd,
        XpcMessageType.SHMEM: XpcShmem,
        XpcMessageType.ARRAY: XpcArray,
    }),  # default=Probe(lookahead=20)),
)

XpcPayload = Struct(
    'magic' / Hex(Const(0x42133742, Int32ul)),
    'protocol_version' / Hex(Const(0x00000005, Int32ul)),
    'message' / XpcObject,
)

XpcWrapper = Struct(
    'magic' / Hex(Const(0x29b00b92, Int32ul)),
    'flags' / Default(XpcFlags, XpcFlags.ALWAYS_SET),
    'size' / Hex(Int64ul),
    'message_id' / Hex(Default(Int64ul, 0)),
    'payload' / If(this.size > 0, FixedSized(this.size, XpcPayload)),
)


def _get_dict_from_xpc_object(xpc_object):
    type_ = xpc_object.type

    if type_ == XpcMessageType.DICTIONARY:
        if xpc_object.data.count == 0:
            return {}
        result = {}
        for entry in xpc_object.data.entries:
            result[entry.key] = _get_dict_from_xpc_object(entry.value)
        return result

    elif type_ == XpcMessageType.ARRAY:
        result = []
        for entry in xpc_object.data.entries:
            result.append(_get_dict_from_xpc_object(entry.value))
        return result

    return xpc_object.data


def get_object_from_xpc_wrapper(payload: bytes):
    payload = XpcWrapper.parse(payload).payload
    if payload is None:
        return None
    return _get_dict_from_xpc_object(payload.message)


def create_xpc_wrapper(d: Mapping) -> bytes:
    xpc_object = {
        'type': XpcMessageType.DICTIONARY,
        'data': {
            'size': 4,
            'count': 0,
            'entries': [],
        }
    }
    xpc_payload = {
        'message': xpc_object
    }
    xpc_wrapper = {
        'size': len(XpcPayload.build(xpc_payload)),
        'payload': xpc_payload,
    }
    return XpcWrapper.build(xpc_wrapper)
