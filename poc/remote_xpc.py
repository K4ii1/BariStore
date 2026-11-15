#!/usr/bin/env python3
# =============================================================================
#  BariSign — RemoteXPC/RSD client (MIT)
#
#  RemoteServiceDiscovery (RSD) runs on the device's tunnel address and speaks
#  a very small subset of HTTP/2 plus Apple's XPC object encoding.  Its reply
#  carries the port of every developer service (installation_proxy, AFC, house
#  arrest, ...).  Only that port map is needed here; the services themselves are
#  plain length-prefixed plists or AFC, implemented in device_services.py.
#
#  No HPACK: Apple's own clients open channels with an *empty* HEADERS frame, so
#  the client sends exactly the frame sequence pmd3/devicectl emit.  Reference
#  (read, not copied): jkcoxson/idevice xpc/{format,http2}.rs (MIT) and
#  pymobiledevice3 remotexpc.py (GPL, protocol reference only).
#
#  UNTESTED ON A DEVICE.  Frame/XPC round-trips are unit-tested on Linux.
# =============================================================================

import struct

HTTP2_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_HEADER = 9
TYPE_DATA = 0x00
TYPE_HEADERS = 0x01
TYPE_RST_STREAM = 0x03
TYPE_SETTINGS = 0x04
TYPE_PING = 0x06
TYPE_GOAWAY = 0x07
TYPE_WINDOW_UPDATE = 0x08
FLAG_END_STREAM = 0x01
FLAG_ACK = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED = 0x08
FLAG_PRIORITY = 0x20

ROOT_CHANNEL = 1
REPLY_CHANNEL = 3
DEFAULT_WINDOW = 65535
MAX_FRAME = 16384

XPC_MAGIC = 0x29B00B92
XPC_PAYLOAD_MAGIC = 0x42133742
XPC_VERSION = 5

T_NULL = 0x1000
T_BOOL = 0x2000
T_INT64 = 0x3000
T_UINT64 = 0x4000
T_DOUBLE = 0x5000
T_DATE = 0x7000
T_DATA = 0x8000
T_STRING = 0x9000
T_UUID = 0xA000
T_ARRAY = 0xE000
T_DICT = 0xF000


class XpcError(Exception):
    pass


def _pad(length):
    return (4 - (length % 4)) % 4


def _encode_obj(value, out):
    if value is None:
        out += struct.pack("<I", T_NULL)
    elif isinstance(value, bool):
        out += struct.pack("<I", T_BOOL) + (b"\x01" if value else b"\x00") + b"\x00\x00\x00"
    elif isinstance(value, int):
        if value < 0:
            out += struct.pack("<Iq", T_INT64, value)
        else:
            out += struct.pack("<IQ", T_UINT64, value)
    elif isinstance(value, float):
        out += struct.pack("<Id", T_DOUBLE, value)
    elif isinstance(value, str):
        raw = value.encode("utf-8") + b"\x00"
        out += struct.pack("<II", T_STRING, len(raw)) + raw + b"\x00" * _pad(len(raw))
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        out += struct.pack("<II", T_DATA, len(raw)) + raw + b"\x00" * _pad(len(raw))
    elif isinstance(value, dict):
        content = bytearray(struct.pack("<I", len(value)))
        for key, item in value.items():
            raw = str(key).encode("utf-8") + b"\x00"
            content += raw + b"\x00" * _pad(len(raw))
            _encode_obj(item, content)
        out += struct.pack("<II", T_DICT, len(content)) + content
    elif isinstance(value, (list, tuple)):
        content = bytearray(struct.pack("<I", len(value)))
        for item in value:
            _encode_obj(item, content)
        out += struct.pack("<II", T_ARRAY, len(content)) + content
    elif isinstance(value, _Uuid):
        out += struct.pack("<I", T_UUID) + value.bytes
    else:
        raise XpcError("cannot encode %r" % (type(value).__name__,))


class _Uuid:
    def __init__(self, raw):
        self.bytes = raw

    def __str__(self):
        h = self.bytes.hex()
        return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])


def uuid_value(text):
    return _Uuid(bytes.fromhex(text.replace("-", "")))


def encode_payload(value):
    out = bytearray(struct.pack("<II", XPC_PAYLOAD_MAGIC, XPC_VERSION))
    _encode_obj(value, out)
    return bytes(out)


def _decode_obj(data, pos):
    if pos + 4 > len(data):
        raise XpcError("truncated XPC object")
    kind = struct.unpack("<I", data[pos:pos + 4])[0]
    pos += 4
    if kind == T_NULL:
        return None, pos
    if kind == T_BOOL:
        if pos + 4 > len(data):
            raise XpcError("truncated bool")
        return data[pos] != 0, pos + 4
    if kind == T_INT64:
        return struct.unpack("<q", data[pos:pos + 8])[0], pos + 8
    if kind == T_UINT64:
        return struct.unpack("<Q", data[pos:pos + 8])[0], pos + 8
    if kind == T_DOUBLE:
        return struct.unpack("<d", data[pos:pos + 8])[0], pos + 8
    if kind == T_DATE:
        return struct.unpack("<Q", data[pos:pos + 8])[0], pos + 8
    if kind in (T_STRING, T_DATA):
        if pos + 4 > len(data):
            raise XpcError("truncated string/data length")
        length = struct.unpack("<I", data[pos:pos + 4])[0]
        pos += 4
        if length > len(data) - pos:
            raise XpcError("truncated string/data")
        raw = data[pos:pos + length]
        pos += length + _pad(length)
        if kind == T_DATA:
            return raw, pos
        return raw.rstrip(b"\x00").decode("utf-8", "replace"), pos
    if kind == T_UUID:
        if pos + 16 > len(data):
            raise XpcError("truncated UUID")
        return _Uuid(data[pos:pos + 16]), pos + 16
    if kind == T_DICT:
        if pos + 4 > len(data):
            raise XpcError("truncated dictionary length")
        pos += 4
        count = struct.unpack("<I", data[pos:pos + 4])[0]
        pos += 4
        result = {}
        for _ in range(count):
            end = data.find(b"\x00", pos)
            if end < 0:
                raise XpcError("unterminated dictionary key")
            key = data[pos:end].decode("utf-8", "replace")
            pos = end + 1
            pos += _pad(len(key) + 1)
            value, pos = _decode_obj(data, pos)
            result[key] = value
        return result, pos
    if kind == T_ARRAY:
        if pos + 4 > len(data):
            raise XpcError("truncated array length")
        pos += 4
        count = struct.unpack("<I", data[pos:pos + 4])[0]
        pos += 4
        items = []
        for _ in range(count):
            item, pos = _decode_obj(data, pos)
            items.append(item)
        return items, pos
    raise XpcError("unknown XPC type 0x%X" % kind)


def decode_payload(data):
    if len(data) < 8:
        raise XpcError("truncated XPC payload header")
    magic, version = struct.unpack("<II", data[:8])
    if magic != XPC_PAYLOAD_MAGIC or version != XPC_VERSION:
        raise XpcError("bad XPC payload header")
    value, _ = _decode_obj(data, 8)
    return value


def encode_wrapper(value, message_id=0, flags=None, wanting_reply=False, with_body=True):
    body = b""
    if with_body:
        body = encode_payload(value)
    if flags is None:
        flags = 0x00000001
        if body:
            flags |= 0x00000100
        if wanting_reply:
            flags |= 0x00010000
    header = struct.pack("<IIQQ", XPC_MAGIC, flags, len(body), message_id)
    return header + body


def decode_wrapper(data):
    if len(data) < 24:
        raise XpcError("truncated XPC wrapper")
    magic, flags, size, message_id = struct.unpack("<IIQQ", data[:24])
    if magic != XPC_MAGIC:
        raise XpcError("bad XPC wrapper magic")
    if size > len(data) - 24:
        raise XpcError("truncated XPC wrapper body")
    body = data[24:24 + size]
    value = decode_payload(body) if size else None
    return flags, message_id, value


class Frame:
    def __init__(self, kind, flags, stream, payload):
        self.kind = kind
        self.flags = flags
        self.stream = stream
        self.payload = payload

    def build(self):
        length = len(self.payload)
        return (length.to_bytes(3, "big") + bytes([self.kind, self.flags])
                + struct.pack(">I", self.stream) + self.payload)


class RemoteXpc:
    """HTTP/2 + XPC client for RSD and RemoteXPC services."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self._buf = b""
        self._msg_id = {ROOT_CHANNEL: 0, REPLY_CHANNEL: 0}
        self._data = {ROOT_CHANNEL: b"", REPLY_CHANNEL: b""}
        self._send_window = DEFAULT_WINDOW
        self._peer_window = DEFAULT_WINDOW
        self._stream_peer = {}
        self.closed = False

    async def _write(self, frame):
        self.writer.write(frame.build())
        await self.writer.drain()

    async def _read_exact(self, size):
        return await self.reader.readexactly(size)

    async def _read_frame(self):
        header = await self._read_exact(FRAME_HEADER)
        length = int.from_bytes(header[:3], "big")
        kind = header[3]
        flags = header[4]
        stream = struct.unpack(">I", header[5:9])[0] & 0x7FFFFFFF
        payload = await self._read_exact(length) if length else b""
        return Frame(kind, flags, stream, payload)

    async def _handle_frame(self, frame):
        if frame.kind == TYPE_SETTINGS:
            if frame.flags & FLAG_ACK:
                return
            pos = 0
            while pos + 6 <= len(frame.payload):
                ident, value = struct.unpack(">HI", frame.payload[pos:pos + 6])
                pos += 6
                if ident == 0x04:
                    delta = value - self._peer_window
                    self._peer_window = value
                    for key in self._stream_peer:
                        self._stream_peer[key] += delta
            await self._write(Frame(TYPE_SETTINGS, FLAG_ACK, 0, b""))
        elif frame.kind == TYPE_WINDOW_UPDATE and len(frame.payload) == 4:
            amount = struct.unpack(">I", frame.payload)[0]
            if frame.stream == 0:
                self._send_window += amount
            else:
                self._stream_peer[frame.stream] = self._stream_peer.get(frame.stream, DEFAULT_WINDOW) + amount
        elif frame.kind == TYPE_PING and not (frame.flags & FLAG_ACK):
            await self._write(Frame(TYPE_PING, FLAG_ACK, 0, frame.payload))
        elif frame.kind == TYPE_RST_STREAM:
            raise XpcError("the device reset XPC stream %d" % frame.stream)
        elif frame.kind == TYPE_GOAWAY:
            text = frame.payload[8:].decode("utf-8", "replace")
            raise XpcError("the device closed RemoteXPC: %s" % text)
        elif frame.kind == TYPE_DATA:
            self._data[frame.stream] = self._data.get(frame.stream, b"") + frame.payload
            if frame.payload:
                amount = len(frame.payload)
                await self._write(Frame(TYPE_WINDOW_UPDATE, 0, 0, struct.pack(">I", amount)))
                await self._write(Frame(TYPE_WINDOW_UPDATE, 0, frame.stream, struct.pack(">I", amount)))

    async def _send_data(self, stream, payload):
        offset = 0
        while offset < len(payload) or (not payload and offset == 0):
            chunk = payload[offset:offset + MAX_FRAME]
            await self._send_chunk(stream, chunk)
            offset += len(chunk)
            if not payload:
                break
        return

    async def _send_chunk(self, stream, chunk):
        while self._send_window < len(chunk):
            frame = await self._read_frame()
            if frame.kind == TYPE_WINDOW_UPDATE and frame.stream == 0:
                self._send_window += struct.unpack(">I", frame.payload)[0]
            else:
                await self._handle_frame(frame)
        await self._write(Frame(TYPE_DATA, 0, stream, chunk))
        self._send_window -= len(chunk)

    def _next_id(self, stream):
        value = self._msg_id[stream]
        self._msg_id[stream] = (value + 1) | 1
        return value

    async def handshake(self):
        self.writer.write(HTTP2_MAGIC)
        await self.writer.drain()
        settings = struct.pack(">HI", 0x03, 100) + struct.pack(">HI", 0x04, 1048576)
        await self._write(Frame(TYPE_SETTINGS, 0, 0, settings))
        await self._write(Frame(TYPE_WINDOW_UPDATE, 0, 0, struct.pack(">I", 983041)))
        await self._write(Frame(TYPE_HEADERS, FLAG_END_HEADERS, ROOT_CHANNEL, b""))
        await self._send_data(ROOT_CHANNEL, encode_wrapper({}, message_id=0, flags=0x0001))
        await self._write(Frame(TYPE_HEADERS, FLAG_END_HEADERS, REPLY_CHANNEL, b""))
        await self._send_data(ROOT_CHANNEL, encode_wrapper(None, message_id=0, flags=0x0201, with_body=False))
        await self._send_data(REPLY_CHANNEL, encode_wrapper(
            None, message_id=0, flags=0x00400001, with_body=False))
        self._msg_id[REPLY_CHANNEL] = 1
        while True:
            frame = await self._read_frame()
            if frame.kind == TYPE_SETTINGS:
                await self._handle_frame(frame)
                break
            await self._handle_frame(frame)

    async def send_request(self, value, wanting_reply=False):
        message_id = self._next_id(ROOT_CHANNEL)
        wrapper = encode_wrapper(value, message_id=message_id, wanting_reply=wanting_reply)
        await self._send_data(ROOT_CHANNEL, wrapper)

    async def receive_response(self):
        while True:
            for channel in (ROOT_CHANNEL, REPLY_CHANNEL):
                buf = self._data.get(channel, b"")
                if not buf:
                    continue
                try:
                    flags, message_id, value = decode_wrapper(buf)
                except XpcError as exc:
                    if "truncated" in str(exc):
                        continue
                    raise
                consumed = 24 + struct.unpack("<Q", buf[8:16])[0]
                self._data[channel] = buf[consumed:]
                if isinstance(value, dict):
                    if value:
                        return value
                elif value is not None:
                    return value
            frame = await self._read_frame()
            await self._handle_frame(frame)

    async def send_device_handshake(self):
        import uuid as _uuid
        await self.send_request({
            "MessageType": "Handshake",
            "MessagingProtocolVersion": 7,
            "UUID": _Uuid(_uuid.uuid4().bytes),
            "Properties": {
                "RemoteXPCVersionFlags": 0x0100000000000006,
                "SensitivePropertiesVisible": True,
            },
            "Services": {},
        })

    async def close(self):
        self.closed = True
        try:
            self.writer.close()
        except Exception:                                       # noqa: BLE001
            pass
        try:
            await self.writer.wait_closed()
        except Exception:                                       # noqa: BLE001
            pass


async def connect_rsd(reader, writer):
    """Run the RSD handshake and return (services, properties, xpc)."""
    client = RemoteXpc(reader, writer)
    await client.handshake()
    await client.send_device_handshake()
    import asyncio
    peer = await asyncio.wait_for(client.receive_response(), 20)
    services = peer.get("Services")
    if not isinstance(services, dict):
        raise XpcError("RSD peer info has no Services dictionary")
    properties = peer.get("Properties") or {}
    return services, properties, client


def service_port(services, name):
    entry = services.get(name)
    if not isinstance(entry, dict):
        raise XpcError("the device does not offer the service %s" % name)
    port = entry.get("Port")
    if isinstance(port, str):
        port = int(port)
    if not isinstance(port, int) or not (0 < port < 65536):
        raise XpcError("service %s has an invalid port" % name)
    return port
