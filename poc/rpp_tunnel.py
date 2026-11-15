#!/usr/bin/env python3
# =============================================================================
#  BariSign — RPPairing control channel + TLS-PSK tunnel (MIT)
#
#  1. pair-verify against the target's _remotepairing._tcp service (plain TCP,
#     "RPPairing" framing, X25519 + Ed25519 + ChaCha20-Poly1305);
#  2. ask for a TCP listener (createListener);
#  3. connect to it and run a TLS 1.2 PSK handshake with the X25519 shared
#     secret as the PSK;
#  4. CDTunnel handshake, then raw IPv6 packets over the TLS stream.
#
#  The result is an L3 link for poc/tcp6.py plus the device's RSD endpoint.
#  Reference (read, not copied): jkcoxson/idevice remote_pairing/{mod,tunnel,
#  tls_psk}.rs (MIT).  UNTESTED ON A DEVICE.
# =============================================================================

import asyncio
import base64
import json
import plistlib
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import tls_psk

MAGIC = b"RPPairing"
CDTUNNEL = b"CDTunnel"
WIRE_VERSION = 19


class PairingTunnelError(Exception):
    pass


def _tlv(data):
    result = {}
    pos = 0
    while pos + 2 <= len(data):
        kind, length = data[pos], data[pos + 1]
        result[kind] = result.get(kind, b"") + data[pos + 2:pos + 2 + length]
        pos += 2 + length
    return result


def load_record(path):
    with open(path, "rb") as handle:
        record = plistlib.load(handle)
    for key in ("private_key", "public_key", "identifier"):
        if not record.get(key):
            raise PairingTunnelError("the pairing file is missing %s" % key)
    if not record.get("alt_irk") and record.get("host_alt_irk"):
        record["alt_irk"] = record["host_alt_irk"]
    if not record.get("identifier") and record.get("host_identifier"):
        record["identifier"] = record["host_identifier"]
    return record


class RemotePairingLink:
    """RPPairing client over an already-open TCP stream."""

    def __init__(self, reader, writer, record):
        self.reader = reader
        self.writer = writer
        self.record = record
        self.sequence = 0
        self.encrypted_sequence = 0
        self.client_cipher = None
        self.server_cipher = None
        self.psk = None
        self.peer = {}

    def _write(self, value):
        body = json.dumps(value).encode()
        self.writer.write(MAGIC + struct.pack(">H", len(body)) + body)

    async def _send_plain(self, value):
        self._write({
            "message": {"plain": {"_0": value}},
            "originatedBy": "host",
            "sequenceNumber": self.sequence,
        })
        self.sequence += 1
        await self.writer.drain()

    async def _recv_plain(self):
        magic = await self.reader.readexactly(len(MAGIC))
        if magic != MAGIC:
            raise PairingTunnelError("the target did not answer with RPPairing framing")
        length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        body = await self.reader.readexactly(length)
        envelope = json.loads(body)
        try:
            return envelope["message"]["plain"]["_0"]
        except (KeyError, TypeError):
            raise PairingTunnelError("unexpected RPPairing envelope")

    async def pair_verify(self):
        private = Ed25519PrivateKey.from_private_bytes(bytes(self.record["private_key"]))
        identifier = str(self.record["identifier"])
        ephemeral = X25519PrivateKey.generate()
        public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        await self._send_plain({
            "request": {"_0": {"handshake": {"_0": {
                "hostOptions": {"attemptPairVerify": True},
                "wireProtocolVersion": WIRE_VERSION,
            }}}}
        })
        response = await self._recv_plain()
        handshake = response.get("response", {}).get("_1", {}).get("handshake", {}).get("_0", {})
        peer = handshake.get("peerDeviceInfo", {})

        def send_pairing(data, new_session):
            self._write({
                "message": {"plain": {"_0": {
                    "event": {"_0": {"pairingData": {"_0": {
                        "data": base64.b64encode(data).decode(),
                        "startNewSession": new_session,
                        "kind": "verifyManualPairing",
                    }}}}
                }}},
                "originatedBy": "host",
                "sequenceNumber": self.sequence,
            })
            self.sequence += 1

        async def receive_pairing():
            reply = await self._recv_plain()
            event = reply.get("event", {}).get("_0", {})
            if "pairingData" in event:
                return _tlv(base64.b64decode(event["pairingData"]["_0"]["data"]))
            raise PairingTunnelError("the target sent no pair-verify data")

        send_pairing(_tlv_encode([(6, b"\x01"), (3, public)]), True)
        data = await receive_pairing()
        if 7 in data or 3 not in data:
            raise PairingTunnelError("pair-verify was refused (is the pairing file still valid?)")
        peer_public = X25519PublicKey.from_public_bytes(data[3])
        shared = ephemeral.exchange(peer_public)
        self.psk = shared

        key = HKDF(algorithm=hashes.SHA512(), length=32,
                   salt=b"Pair-Verify-Encrypt-Salt",
                   info=b"Pair-Verify-Encrypt-Info").derive(shared)
        cipher = ChaCha20Poly1305(key)
        signbuf = public + identifier.encode() + data[3]
        signature = private.sign(signbuf)
        encrypted = cipher.encrypt(b"\x00\x00\x00\x00PV-Msg03",
                                   _tlv_encode([(1, identifier.encode()), (10, signature)]), b"")
        send_pairing(_tlv_encode([(6, b"\x03"), (5, encrypted)]), False)
        result = await receive_pairing()
        if 7 in result:
            raise PairingTunnelError("pair-verify failed: the target does not know this host")

        client_key = HKDF(algorithm=hashes.SHA512(), length=32, salt=None,
                          info=b"ClientEncrypt-main").derive(shared)
        server_key = HKDF(algorithm=hashes.SHA512(), length=32, salt=None,
                          info=b"ServerEncrypt-main").derive(shared)
        self.client_cipher = ChaCha20Poly1305(client_key)
        self.server_cipher = ChaCha20Poly1305(server_key)
        self.peer = peer
        return peer

    async def encrypted_request(self, value):
        if self.client_cipher is None:
            raise PairingTunnelError("pair-verify has not completed")
        nonce = struct.pack("<Q", self.encrypted_sequence) + b"\x00" * 4
        ciphertext = self.client_cipher.encrypt(nonce, json.dumps(value).encode(), b"")
        self._write({
            "message": {"streamEncrypted": {"_0": base64.b64encode(ciphertext).decode()}},
            "originatedBy": "host",
            "sequenceNumber": self.sequence,
        })
        await self.writer.drain()
        self.encrypted_sequence += 1
        reply = await self._recv_plain_stream()
        encrypted = reply.get("message", {}).get("streamEncrypted", {}).get("_0")
        if encrypted is None:
            raise PairingTunnelError("the target sent no encrypted reply")
        plaintext = self.server_cipher.decrypt(nonce, base64.b64decode(encrypted), b"")
        value = json.loads(plaintext)
        response = value.get("response", {}).get("_1")
        if response is None:
            raise PairingTunnelError("the target refused the request: %r" % (value,))
        if "errorExtended" in response:
            raise PairingTunnelError(
                "the target refused the request: %r" % (response["errorExtended"],))
        return response

    async def _recv_plain_stream(self):
        magic = await self.reader.readexactly(len(MAGIC))
        if magic != MAGIC:
            raise PairingTunnelError("bad RPPairing framing")
        length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        return json.loads(await self.reader.readexactly(length))

    async def create_tcp_listener(self):
        response = await self.encrypted_request({
            "request": {"_0": {"createListener": {
                "key": base64.b64encode(self.psk).decode(),
                "transportProtocolType": "tcp",
            }}}
        })
        listener = response.get("createListener") or {}
        port = listener.get("port")
        if not isinstance(port, int):
            raise PairingTunnelError("the target did not return a tunnel port")
        return port


def _tlv_encode(entries):
    out = bytearray()
    for kind, value in entries:
        value = bytes(value)
        offset = 0
        if not value:
            out += bytes([kind, 0])
        while offset < len(value):
            chunk = value[offset:offset + 255]
            out += bytes([kind, len(chunk)]) + chunk
            offset += len(chunk)
    return bytes(out)


class TunnelLink:
    """Raw IPv6 packet link over the TLS-PSK CDTunnel stream."""

    def __init__(self, stream):
        self.stream = stream
        self._send_lock = asyncio.Lock()

    def send(self, packet):
        # The TLS layer already splits records at 16 KiB; this is called from
        # the TCP stack's timer/ACK paths, which must not block.
        self.stream.write(packet)

    async def recv(self):
        header = await self.stream.readexactly(40)
        if header[0] >> 4 != 6:
            raise PairingTunnelError("the tunnel sent a non-IPv6 packet")
        length = struct.unpack(">H", header[4:6])[0]
        body = await self.stream.readexactly(length) if length else b""
        return header + body


async def open_tunnel(host, port, record, timeout=20):
    """Pair-verify, create the listener, run TLS-PSK + CDTunnel."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    control = RemotePairingLink(reader, writer, record)
    await control.pair_verify()
    listener_port = await control.create_tcp_listener()

    reader2, writer2 = await asyncio.wait_for(
        asyncio.open_connection(host, listener_port), timeout)
    stream = await tls_psk.connect(reader2, writer2, control.psk)
    request = CDTUNNEL + struct.pack(">H", len(json.dumps(
        {"type": "clientHandshakeRequest", "mtu": 16000}))) + json.dumps(
        {"type": "clientHandshakeRequest", "mtu": 16000}).encode()
    stream.write(request)
    await stream.drain()
    magic = await stream.readexactly(len(CDTUNNEL))
    if magic != CDTUNNEL:
        raise PairingTunnelError("the target did not answer the CDTunnel handshake")
    length = struct.unpack(">H", await stream.readexactly(2))[0]
    response = json.loads(await stream.readexactly(length))
    client = response.get("clientParameters") or {}
    address = client.get("address")
    server_address = response.get("serverAddress")
    rsd_port = response.get("serverRSDPort")
    if not address or not server_address or not isinstance(rsd_port, int):
        raise PairingTunnelError("incomplete CDTunnel handshake: %r" % (response,))
    return {
        "control": control,
        "stream": stream,
        "link": TunnelLink(stream),
        "client_address": address,
        "server_address": server_address,
        "rsd_port": rsd_port,
        "mtu": client.get("mtu", 1500),
        "peer": getattr(control, "peer", {}),
    }
