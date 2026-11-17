#!/usr/bin/env python3
"""Mock-device test of pair-verify + TLS-PSK + CDTunnel."""
import asyncio
import base64
import json
import os
import ssl
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from baristore import pairing, tunnel


def tlv_encode(entries):
    out = bytearray()
    for kind, value in entries:
        value = bytes(value)
        offset = 0
        while offset < len(value) or not value:
            chunk = value[offset:offset + 255]
            out += bytes([kind, len(chunk)]) + chunk
            offset += 255
            if not value:
                break
    return bytes(out)


def tlv_decode(data):
    result = {}
    pos = 0
    while pos + 2 <= len(data):
        kind, length = data[pos], data[pos + 1]
        result[kind] = result.get(kind, b"") + data[pos + 2:pos + 2 + length]
        pos += 2 + length
    return result


class MockDevice:
    def __init__(self):
        self.shared = None
        self.port = 0
        self.tls_port = 0

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def send(self, writer, value, seq=0):
        envelope = {
            "message": {"plain": {"_0": value}},
            "originatedBy": "device",
            "sequenceNumber": seq,
        }
        body = json.dumps(envelope).encode()
        writer.write(b"RPPairing" + struct.pack(">H", len(body)) + body)
        await writer.drain()

    async def recv(self, reader):
        magic = await reader.readexactly(9)
        assert magic == b"RPPairing"
        length = struct.unpack(">H", await reader.readexactly(2))[0]
        return json.loads(await reader.readexactly(length))

    async def handle(self, reader, writer):
        try:
            envelope = await self.recv(reader)
        except asyncio.IncompleteReadError:
            writer.close()
            return
        request = envelope["message"]["plain"]["_0"]
        assert "handshake" in request["request"]["_0"]
        await self.send(
            writer,
            {
                "response": {
                    "forRequestIdentifier": 0,
                    "_1": {
                        "handshake": {
                            "_0": {
                                "wireProtocolVersion": 26,
                                "peerDeviceInfo": {
                                    "name": "MockTarget",
                                    "identifier": "MOCK",
                                    "model": "iPhone17,1",
                                    "udid": "b" * 40,
                                },
                            }
                        }
                    },
                }
            },
        )

        envelope = await self.recv(reader)
        pairing_data = envelope["message"]["plain"]["_0"]["event"]["_0"]["pairingData"]["_0"]
        m1 = tlv_decode(base64.b64decode(pairing_data["data"]))
        assert m1[6] == b"\x01"
        device_private = X25519PrivateKey.generate()
        device_public = device_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        await self.send(
            writer,
            {
                "event": {
                    "_0": {
                        "pairingData": {
                            "_0": {
                                "data": base64.b64encode(
                                    tlv_encode([(6, b"\x02"), (3, device_public)])
                                ).decode(),
                                "startNewSession": False,
                                "kind": "verifyManualPairing",
                            }
                        }
                    }
                }
            },
        )

        envelope = await self.recv(reader)
        pairing_data = envelope["message"]["plain"]["_0"]["event"]["_0"]["pairingData"]["_0"]
        m3 = tlv_decode(base64.b64decode(pairing_data["data"]))
        assert m3[6] == b"\x03"
        host_public = X25519PublicKey.from_public_bytes(m1[3])
        self.shared = device_private.exchange(host_public)
        verify_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Verify-Encrypt-Salt",
            info=b"Pair-Verify-Encrypt-Info",
        ).derive(self.shared)
        cipher = ChaCha20Poly1305(verify_key)
        plaintext = cipher.decrypt(b"\x00\x00\x00\x00PV-Msg03", m3[5], b"")
        inner = tlv_decode(plaintext)
        assert 1 in inner and 10 in inner
        await self.send(
            writer,
            {
                "event": {
                    "_0": {
                        "pairingData": {
                            "_0": {
                                "data": base64.b64encode(tlv_encode([(6, b"\x04")])).decode(),
                                "startNewSession": False,
                                "kind": "verifyManualPairing",
                            }
                        }
                    }
                }
            },
        )

        client_key = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"ClientEncrypt-main"
        ).derive(self.shared)
        server_key = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"ServerEncrypt-main"
        ).derive(self.shared)
        self.client_cipher = ChaCha20Poly1305(client_key)
        self.server_cipher = ChaCha20Poly1305(server_key)

        envelope = await self.recv(reader)
        encrypted = base64.b64decode(envelope["message"]["streamEncrypted"]["_0"])
        nonce = b"\x00" * 12
        request = json.loads(self.client_cipher.decrypt(nonce, encrypted, b""))
        listener = request["request"]["_0"]["createListener"]
        assert base64.b64decode(listener["key"]) == self.shared
        self.tls_server = await self.start_tls()
        reply = {"response": {"_1": {"createListener": {"port": self.tls_port}}}}
        ciphertext = self.server_cipher.encrypt(nonce, json.dumps(reply).encode(), b"")
        out_env = json.dumps(
            {
                "message": {"streamEncrypted": {"_0": base64.b64encode(ciphertext).decode()}},
                "originatedBy": "device",
                "sequenceNumber": 0,
            }
        ).encode()
        writer.write(b"RPPairing" + struct.pack(">H", len(out_env)) + out_env)
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.close()

    async def start_tls(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("PSK-AES256-CBC-SHA384")
        ctx.set_psk_server_callback(lambda _identity: self.shared)

        async def handle(reader, writer):
            magic = await reader.readexactly(8)
            assert magic == b"CDTunnel"
            length = struct.unpack(">H", await reader.readexactly(2))[0]
            request = json.loads(await reader.readexactly(length))
            assert request["type"] == "clientHandshakeRequest"
            reply = json.dumps(
                {
                    "clientParameters": {"address": "fd00::2", "mtu": 16000},
                    "serverAddress": "fd00::1",
                    "serverRSDPort": 12345,
                }
            ).encode()
            writer.write(b"CDTunnel" + struct.pack(">H", len(reply)) + reply)
            await writer.drain()
            while True:
                try:
                    header = await reader.readexactly(40)
                except asyncio.IncompleteReadError:
                    return
                length = struct.unpack(">H", header[4:6])[0]
                body = await reader.readexactly(length) if length else b""
                writer.write(header + body)
                await writer.drain()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
        self.tls_port = server.sockets[0].getsockname()[1]
        return server


async def main():
    identity = pairing.HostIdentity.generate()
    record_path = os.path.join("/tmp/opencode", "mock-rppairing-record.plist")
    record = pairing.PairingRecord(identity, {"alt_irk": b"\x00" * 16, "udid": "b" * 40})
    record.write(record_path)
    loaded = tunnel.load_record(record_path)
    dev = MockDevice()
    port = await dev.start()
    tun = await tunnel.open_tunnel("127.0.0.1", port, loaded, timeout=10)
    assert tun["client_address"] == "fd00::2"
    assert tun["server_address"] == "fd00::1"
    assert tun["rsd_port"] == 12345
    packet = (
        struct.pack(">IHBB", 6 << 28, 8, 59, 64)
        + bytes.fromhex("fd000000000000000000000000000002")
        + bytes.fromhex("fd000000000000000000000000000001")
        + b"\x00" * 8
    )
    tun["link"].send(packet)
    await tun["stream"].drain()
    echoed = await asyncio.wait_for(tun["link"].recv(), 5)
    assert echoed[:40] == packet[:40]
    tun["stream"].close()
    tun["control"].writer.close()
    await asyncio.sleep(0.1)
    dev.server.close()
    await dev.server.wait_closed()
    dev.tls_server.close()
    await dev.tls_server.wait_closed()
    os.unlink(record_path)


if __name__ == "__main__":
    asyncio.run(main())
    print("ok  pair-verify + TLS-PSK + CDTunnel")
