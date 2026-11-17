#!/usr/bin/env python3
"""Round-trip test of the device-initiated pairing host (including pre-computed SRP and probe resilience)."""
import asyncio
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from baristore import pairing


def tlv_encode(entries):
    out = bytearray()
    for kind, value in entries:
        value = bytes(value)
        offset = 0
        if not value:
            out += bytes([kind, 0])
        while offset < len(value):
            chunk = value[offset:offset + 255]
            out += bytes([kind, len(chunk)]) + chunk
            offset += 255
    return bytes(out)


class MockClient:
    def __init__(self, reader, writer, pin):
        self.reader = reader
        self.writer = writer
        self.pin = pin
        self.sequence = 0

    async def send(self, value):
        envelope = {
            "message": {"plain": {"_0": value}},
            "originatedBy": "host",
            "sequenceNumber": self.sequence,
        }
        self.sequence += 1
        body = json.dumps(envelope).encode()
        self.writer.write(b"RPPairing" + struct.pack(">H", len(body)) + body)
        await self.writer.drain()

    async def recv(self):
        assert await self.reader.readexactly(9) == b"RPPairing"
        length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        envelope = json.loads(await self.reader.readexactly(length))
        return envelope["message"]["plain"]["_0"]

    async def pairing_event(self, data):
        await self.send(
            {
                "event": {
                    "_0": {
                        "pairingData": {
                            "_0": {
                                "data": base64.b64encode(data).decode(),
                                "startNewSession": False,
                                "kind": "setupManualPairing",
                            }
                        }
                    }
                }
            }
        )

    async def pairing_data(self):
        response = await self.recv()
        return pairing.tlv_decode(
            base64.b64decode(response["event"]["_0"]["pairingData"]["_0"]["data"])
        )

    async def run(self):
        await self.send(
            {
                "request": {
                    "_0": {
                        "handshake": {
                            "_0": {
                                "hostOptions": {"attemptPairVerify": False},
                                "wireProtocolVersion": 26,
                            }
                        }
                    }
                }
            }
        )
        handshake = await self.recv()
        assert handshake["response"]["_1"]["handshake"]["_0"]["deviceOptions"]["allowsPairSetup"]

        await self.pairing_event(tlv_encode([(0, b"\x00"), (6, b"\x01")]))
        m2 = await self.pairing_data()
        salt, b_pub = m2[2], m2[3]

        n, g, k = pairing.SRP_N, pairing.SRP_G, pairing.SRP_K
        a = int.from_bytes(os.urandom(32), "big")
        A = pow(g, a, n)
        B = int.from_bytes(b_pub, "big")
        u = pairing._hi(pairing._pad(A), pairing._pad(B))
        x = pairing._hi(salt, pairing._h(("Pair-Setup:%s" % self.pin).encode()))
        S = pow((B - k * pow(g, x, n)) % n, a + u * x, n)
        key = pairing._h(pairing._min_bytes(S))
        group = pairing._hi(pairing._min_bytes(n)) ^ pairing._hi(pairing._min_bytes(g))
        proof = pairing._h(
            pairing._min_bytes(group),
            pairing._min_bytes(pairing._hi(b"Pair-Setup")),
            salt,
            pairing._min_bytes(A),
            b_pub,
            key,
        )
        await self.pairing_event(
            tlv_encode([(3, pairing._min_bytes(A)), (4, proof), (6, b"\x03")])
        )
        m4 = await self.pairing_data()
        assert m4[6] == b"\x04"
        assert m4[4] == pairing._h(pairing._min_bytes(A), proof, key)

        setup_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Setup-Encrypt-Salt",
            info=b"Pair-Setup-Encrypt-Info",
        ).derive(key)
        cipher = ChaCha20Poly1305(setup_key)
        device_key = Ed25519PrivateKey.generate()
        device_public = device_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        info = pairing.opack_encode(
            {
                "altIRK": b"\x11" * 16,
                "accountID": "DEVICE-ACCOUNT",
                "model": "iPhone17,1",
                "name": "Target",
                "remotepairing_udid": "c" * 40,
            }
        )
        identity = tlv_encode(
            [
                (1, b"DEVICE-ID"),
                (3, device_public),
                (10, b"\x00" * 64),
                (17, info),
            ]
        )
        m5 = tlv_encode(
            [(5, cipher.encrypt(b"\x00\x00\x00\x00PS-Msg05", identity, b"")), (6, b"\x05")]
        )
        await self.pairing_event(m5)

        m6 = await self.pairing_data()
        assert m6[6] == b"\x06"
        plaintext = cipher.decrypt(b"\x00\x00\x00\x00PS-Msg06", m6[5], b"")
        accessory = pairing.tlv_decode(plaintext)
        assert len(accessory[3]) == 32
        assert len(accessory[10]) == 64
        return accessory, key


async def main():
    identity = pairing.HostIdentity.generate()
    precomputed = pairing.prepare_srp_server("654321")
    assert precomputed.pin == "654321"
    pins = []

    async def handler(reader, writer):
        host = pairing.PairableHost(
            reader, writer, identity, precomputed_srp=precomputed
        )
        try:
            await host.accept(lambda p: pins.append(p))
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = MockClient(reader, writer, "654321")
    await asyncio.wait_for(client.run(), 10)
    assert pins == ["654321"]
    writer.close()
    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
    print("ok  pairing host round-trip")
