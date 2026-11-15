#!/usr/bin/env python3
"""Linux unit tests for the pure protocol layers (no device, no network)."""
import asyncio
import base64
import os
import plistlib
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import device_services
import mdns
import pairing
import remote_xpc


def test_siphash_vectors():
    key = bytes(range(16))
    assert pairing.siphash24(key, b"") == 0x726FDB47DD0E0E31
    assert pairing.siphash24(key, bytes([0])) == 0x74F839C593DC67FD
    assert pairing.siphash24(key, bytes(range(7))) == 0xAB0200F58B01D137


def test_auth_tag_vector():
    # idevice/PMD3 test vector
    alt_irk = base64.b64decode("Mgp6ZGPzXM2ku9br46vsiw==")
    identifier = "2BE6E510-0325-4365-923E-B14C6F57DB3A"
    tag = pairing.auth_tag(alt_irk, identifier)
    assert base64.b64encode(tag).decode() == "kXjlTr2l"


def test_tlv_roundtrip_chunking():
    value = bytes(range(256)) * 3
    encoded = pairing.tlv_encode([(3, value), (6, b"\x01")])
    decoded = pairing.tlv_decode(encoded)
    assert decoded[3] == value
    assert decoded[6] == b"\x01"


def test_opack_roundtrip():
    value = {
        "altIRK": bytes(range(16)),
        "btAddr": "11:22:33:44:55:66",
        "mac": b"\x11\x22\x33\x44\x55\x66",
        "remotepairing_serial_number": "AAAAAAAAAAAA",
        "accountID": "ABC",
        "model": "iPhone17,1",
        "name": "Target",
        "zero": 0,
        "big": 70000,
        "yes": True,
    }
    assert pairing.opack_decode(pairing.opack_encode(value)) == value


def test_opack_backref():
    # {"name":"ABC","accountID":"ABC"} with the second "ABC" as a back-reference
    # (tag 0xA0 = first interned scalar).
    payload = b"\xE2" + b"\x44name" + b"\x43ABC" + b"\x49accountID" + b"\xA1"
    assert pairing.opack_decode(payload) == {"name": "ABC", "accountID": "ABC"}


def test_xpc_encoding():
    payload = remote_xpc.encode_payload({})
    assert payload == (struct.pack("<II", 0x42133742, 5)
                       + struct.pack("<II", 0xF000, 4)
                       + struct.pack("<I", 0))
    wrapper = remote_xpc.encode_wrapper({}, message_id=0, flags=0x0001)
    assert wrapper[:24] == struct.pack("<IIQQ", 0x29B00B92, 0x0001, len(payload), 0)
    flags, message_id, value = remote_xpc.decode_wrapper(wrapper)
    assert flags == 1 and message_id == 0 and value == {}


def test_xpc_roundtrip():
    value = {"MessageType": "Handshake", "Services": {"a": {"Port": "1234"}},
             "N": 7, "U": 2 ** 40, "B": True, "D": b"\x00\x01\x02", "A": [1, "x"]}
    flags, message_id, decoded = remote_xpc.decode_wrapper(
        remote_xpc.encode_wrapper(value, message_id=9, wanting_reply=True))
    assert flags == (0x0001 | 0x0100 | 0x10000)
    assert message_id == 9
    assert decoded == value


def _name(text):
    out = b""
    for label in text.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _rr(name, rtype, rdata):
    return name + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata


def test_mdns_parser():
    service = "_remotepairing._tcp.local"
    instance = "Target._remotepairing._tcp.local"
    host = "target.local"
    ptr = _rr(_name(service), 12, _name(instance))
    srv = _rr(_name(instance), 33, struct.pack(">HHH", 0, 0, 49152) + _name(host))
    txt_raw = b"\x0eidentifier=ABC"
    txt = _rr(_name(instance), 16, txt_raw)
    addr = _rr(_name(host), 1, bytes([192, 168, 1, 5]))
    packet = struct.pack(">HHHHHH", 0, 0x8400, 0, 4, 0, 0) + ptr + srv + txt + addr
    records = mdns.parse_packet(packet)
    services = mdns._assemble(records, service)
    assert len(services) == 1
    entry = services[0]
    assert entry["port"] == 49152
    assert entry["properties"]["identifier"] == "ABC"
    assert entry["addresses"] == ["192.168.1.5"]


def test_mdns_compression():
    # PTR rdata is a pointer to the question name at offset 12.
    name = _name("_remotepairing._tcp.local")
    header = struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = name + struct.pack(">HH", 12, 1)
    ptr = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, 2) + b"\xc0\x0c"
    packet = header + question + ptr
    records = mdns.parse_packet(packet)
    assert records[0]["type"] == 12
    assert records[0]["target"] == "_remotepairing._tcp.local"


# --- service protocol mocks -------------------------------------------------

class DirectConnection:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def readexactly(self, size):
        return await self.reader.readexactly(size)

    def write(self, data):
        self.writer.write(data)

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()


class DirectStack:
    async def connect(self, host, port):
        reader, writer = await asyncio.open_connection(host, port)
        return DirectConnection(reader, writer)


async def _read_plist(reader):
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    return plistlib.loads(await reader.readexactly(length))


async def _send_plist(writer, value):
    payload = plistlib.dumps(value, fmt=plistlib.FMT_XML)
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


async def _afc_server(reader, writer):
    while True:
        try:
            header = await reader.readexactly(40)
        except (asyncio.IncompleteReadError, ConnectionError):
            return
        entire = struct.unpack("<Q", header[8:16])[0]
        op = struct.unpack("<Q", header[32:40])[0]
        payload = await reader.readexactly(entire - 40) if entire > 40 else b""
        if op == device_services.OP_FILE_OPEN:
            body = struct.pack("<Q", 77)
            reply_op = device_services.OP_DATA
        else:
            body = b""
            reply_op = device_services.OP_DATA
        writer.write(device_services.AFC_MAGIC
                     + struct.pack("<QQQQ", 40 + len(body), 40 + len(body), 0, reply_op)
                     + body)
        await writer.drain()


def test_afc_upload():
    async def main():
        server = await asyncio.start_server(_afc_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        afc = device_services.Afc(device_services.LockdownConnection(reader, writer))
        await afc.upload("/PublicStaging/x.ipa", b"hello" * 50000)
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
    asyncio.run(main())


def test_rsd_handshake():
    async def handler(reader, writer):
        assert await reader.readexactly(len(remote_xpc.HTTP2_MAGIC)) == remote_xpc.HTTP2_MAGIC
        # read the client's SETTINGS, WINDOW_UPDATE, HEADERS, DATA ... then answer.
        frames = []
        for _ in range(7):
            header = await reader.readexactly(9)
            length = int.from_bytes(header[:3], "big")
            body = await reader.readexactly(length) if length else b""
            frames.append((header[3], body))
        # SETTINGS (empty), then HEADERS 3, DATA 3 handshake (flags 0x00400001)
        writer.write(remote_xpc.Frame(remote_xpc.TYPE_SETTINGS, 0, 0, b"").build())
        peer = {"Services": {"com.apple.afc.shim.remote": {"Port": "1234"}},
                "Properties": {"UniqueDeviceID": "a" * 40, "ProductType": "iPhone17,1"}}
        payload = remote_xpc.encode_wrapper(peer, message_id=1, flags=0x0001)
        writer.write(remote_xpc.Frame(remote_xpc.TYPE_DATA, 0, 1, payload).build())
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()

    async def main():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        services, properties, client = await remote_xpc.connect_rsd(reader, writer)
        assert properties["UniqueDeviceID"] == "a" * 40
        assert remote_xpc.service_port(services, "com.apple.afc.shim.remote") == 1234
        await client.close()
        server.close()
        await server.wait_closed()
    asyncio.run(main())


def test_lockdown_and_install():
    install_commands = []

    async def afc_handler(reader, writer):
        await _send_plist(writer, {"Request": "RSDCheckin"})
        await _read_plist(reader)
        await _send_plist(writer, {"Request": "StartService"})
        await _afc_server(reader, writer)

    async def install_handler(reader, writer):
        await _send_plist(writer, {"Request": "RSDCheckin"})
        request = await _read_plist(reader)
        assert request["Request"] == "RSDCheckin"
        await _send_plist(writer, {"Request": "StartService"})
        command = await _read_plist(reader)
        install_commands.append(command)
        await _send_plist(writer, {"Status": "CreatingStagingDirectory", "PercentComplete": 5})
        await _send_plist(writer, {"Status": "Complete"})

    async def main():
        afc_server = await asyncio.start_server(afc_handler, "127.0.0.1", 0)
        install_server = await asyncio.start_server(install_handler, "127.0.0.1", 0)
        stack = DirectStack()
        await device_services.install_ipa(
            stack, "127.0.0.1",
            install_server.sockets[0].getsockname()[1],
            afc_server.sockets[0].getsockname()[1],
            __file__, log=lambda text: None)
        assert install_commands[0]["ClientOptions"] == {"PackageType": "Developer"}
        afc_server.close()
        install_server.close()
        await afc_server.wait_closed()
        await install_server.wait_closed()
    asyncio.run(main())


def test_srp_roundtrip():
    # Client side is implemented here independently from the server formulas.
    import hashlib
    import secrets

    pin = "123456"
    salt = bytes(range(16))
    server = pairing.SrpServer(pin, salt)
    n, g = pairing.SRP_N, pairing.SRP_G
    k = pairing.SRP_K
    a = secrets.randbits(256)
    A = pow(g, a, n)
    server.process(pairing._min_bytes(A))
    u = pairing._hi(pairing._pad(A), pairing._pad(server.public))
    x = pairing._hi(salt, pairing._h(("Pair-Setup:%s" % pin).encode()))
    S = pow((server.public - k * pow(g, x, n)) % n, a + u * x, n)
    K = pairing._h(pairing._min_bytes(S))
    assert K == server.key
    group = pairing._hi(pairing._min_bytes(n)) ^ pairing._hi(pairing._min_bytes(g))
    M1 = pairing._h(pairing._min_bytes(group),
                    pairing._min_bytes(pairing._hi(b"Pair-Setup")),
                    salt, pairing._min_bytes(A), pairing._min_bytes(server.public), K)
    assert server.verify(M1)
    M2 = pairing._h(pairing._min_bytes(A), M1, K)
    assert server.proof == M2


if __name__ == "__main__":
    functions = [(name, value) for name, value in sorted(globals().items())
                 if name.startswith("test_") and callable(value)]
    for name, function in functions:
        function()
        print("ok  %s" % name)
    print("%d tests passed" % len(functions))
