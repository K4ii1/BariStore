#!/usr/bin/env python3
# =============================================================================
#  BariSign — device-initiated RPPairing host (MIT)
#
#  The TARGET pairs from Settings > Developer > Paired Macs.  It connects to the
#  signer's `_remotepairing-pairable-host._tcp` service and runs Apple's
#  Pair-Setup (SRP-6a over 3072-bit group, SHA-512, TLV8, OPACK).
#
#  SRP and TLV are implemented from RFC 5054 / RFC 2945 and Apple's public
#  pairing formats.  OPACK is decoded/encoded from the format documented by the
#  MIT jkcoxson/idevice source (opack.rs, read not copied).
#
#  UNTESTED ON A DEVICE.  TLV/OPACK/SRP round-trips are unit-tested on Linux.
# =============================================================================

import base64
import hashlib
import hmac
import os
import plistlib
import secrets
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- TLV8 -------------------------------------------------------------------

TLV_METHOD = 0
TLV_IDENTIFIER = 1
TLV_SALT = 2
TLV_PUBLIC_KEY = 3
TLV_PROOF = 4
TLV_ENCRYPTED_DATA = 5
TLV_STATE = 6
TLV_ERROR = 7
TLV_SIGNATURE = 10
TLV_INFO = 17


def tlv_encode(entries):
    out = bytearray()
    for kind, value in entries:
        value = bytes(value)
        if not value:
            out += bytes([kind, 0])
            continue
        offset = 0
        while offset < len(value):
            chunk = value[offset:offset + 255]
            out += bytes([kind, len(chunk)]) + chunk
            offset += len(chunk)
    return bytes(out)


def tlv_decode(data):
    result = {}
    pos = 0
    while pos + 2 <= len(data):
        kind, length = data[pos], data[pos + 1]
        value = data[pos + 2:pos + 2 + length]
        if len(value) < length:
            raise ValueError("truncated TLV")
        result[kind] = result.get(kind, b"") + value
        pos += 2 + length
    return result

# --- SRP-6a (RFC 5054, 3072-bit group) -------------------------------------

_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411"
    "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08"
    "CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760273"
    "3EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
SRP_N = int(_N_HEX, 16)
SRP_G = 5
SRP_PRIVATE_BITS = 1024
SRP_USERNAME = "Pair-Setup"
SRP_PAD = (SRP_N.bit_length() + 7) // 8


def _min_bytes(value):
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _pad(value):
    return value.to_bytes(SRP_PAD, "big")


def _h(*parts):
    return hashlib.sha512(b"".join(parts)).digest()


def _hi(*parts):
    return int.from_bytes(_h(*parts), "big")


SRP_K = _hi(_min_bytes(SRP_N), _pad(SRP_G))


class SrpServer:
    def __init__(self, pin, salt, private=None):
        self.username = SRP_USERNAME
        self.salt = salt
        x = _hi(salt, _h(("%s:%s" % (SRP_USERNAME, pin)).encode()))
        self.verifier = pow(SRP_G, x, SRP_N)
        self.private = private or secrets.randbits(SRP_PRIVATE_BITS)
        self.public = (SRP_K * self.verifier + pow(SRP_G, self.private, SRP_N)) % SRP_N
        self.key = b""
        self.proof = b""
        self.expected_client_proof = b""

    def public_bytes(self):
        return _min_bytes(self.public)

    def process(self, client_public_bytes):
        a = int.from_bytes(client_public_bytes, "big")
        if a % SRP_N == 0:
            raise ValueError("invalid SRP client public value")
        u = _hi(_pad(a), _pad(self.public))
        premaster = pow((a * pow(self.verifier, u, SRP_N)) % SRP_N, self.private, SRP_N)
        self.key = _h(_min_bytes(premaster))
        group_hash = _hi(_min_bytes(SRP_N)) ^ _hi(_min_bytes(SRP_G))
        self.expected_client_proof = _h(
            _min_bytes(group_hash), _min_bytes(_hi(SRP_USERNAME.encode())), self.salt,
            _min_bytes(a), _min_bytes(self.public), self.key)
        self.proof = _h(_min_bytes(a), self.expected_client_proof, self.key)

    def verify(self, client_proof):
        return bool(self.expected_client_proof) and hmac.compare_digest(
            client_proof, self.expected_client_proof)

# --- OPACK (the subset Apple sends in Pair-Setup M5/M6) ---------------------


def opack_encode(value):
    out = bytearray()
    _opack_encode(value, out)
    return bytes(out)


def _opack_encode(value, out):
    if isinstance(value, bool):
        out.append(0x01 if value else 0x02)
    elif isinstance(value, int):
        if 0 <= value <= 0x27:
            out.append(value + 8)
        elif value <= 0xFF:
            out += b"\x30" + struct.pack("<B", value)
        elif value <= 0xFFFF:
            out += b"\x31" + struct.pack("<H", value)
        elif value <= 0xFFFFFFFF:
            out += b"\x32" + struct.pack("<I", value)
        else:
            out += b"\x33" + struct.pack("<Q", value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        _opack_len(out, len(raw), 0x40, 0x61, 0x62, 0x63, 0x64)
        out += raw
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        _opack_len(out, len(raw), 0x70, 0x91, 0x92, 0x93, 0x94)
        out += raw
    elif isinstance(value, dict):
        if len(value) < 15:
            out.append(0xE0 + len(value))
        else:
            out.append(0xEF)
        for key, item in value.items():
            _opack_encode(str(key), out)
            _opack_encode(item, out)
        if len(value) >= 15:
            out.append(0x03)
    elif isinstance(value, (list, tuple)):
        if len(value) < 15:
            out.append(0xD0 + len(value))
        else:
            out.append(0xDF)
        for item in value:
            _opack_encode(item, out)
        if len(value) >= 15:
            out.append(0x03)
    else:
        raise ValueError("cannot OPACK-encode %r" % (type(value).__name__,))


def _opack_len(out, length, inline, u8, u16, u32, u64):
    if length <= 0x20:
        out.append(inline + length)
    elif length <= 0xFF:
        out += bytes([u8, length])
    elif length <= 0xFFFF:
        out.append(u16)
        out += struct.pack("<H", length)
    elif length <= 0xFFFFFFFF:
        out.append(u32)
        out += struct.pack("<I", length)
    else:
        out.append(u64)
        out += struct.pack("<Q", length)


def opack_decode(data):
    value, offset, _ = _opack_decode(data, 0, [])
    if offset != len(data):
        raise ValueError("trailing bytes in OPACK payload")
    return value


def _opack_decode(data, pos, objects):
    if pos >= len(data):
        raise ValueError("truncated OPACK")
    tag = data[pos]
    pos += 1
    if tag == 0x01:
        return True, pos, objects
    if tag == 0x02:
        return False, pos, objects
    if 0x08 <= tag <= 0x2F:
        value = tag - 8
        return _remember(objects, value), pos, objects
    if tag in (0x30, 0x31, 0x32, 0x33):
        size = {0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8}[tag]
        value = int.from_bytes(data[pos:pos + size], "little")
        return _remember(objects, value), pos + size, objects
    if 0x40 <= tag <= 0x64:
        length, pos = _opack_read_len(data, pos, tag, 0x40, 0x61, 0x62, 0x63, 0x64)
        raw = data[pos:pos + length]
        return _remember(objects, raw.decode("utf-8")), pos + length, objects
    if 0x70 <= tag <= 0x94:
        length, pos = _opack_read_len(data, pos, tag, 0x70, 0x91, 0x92, 0x93, 0x94)
        raw = bytes(data[pos:pos + length])
        return _remember(objects, raw), pos + length, objects
    if 0xA0 <= tag <= 0xC4:
        if tag <= 0xC0:
            index = tag - 0xA0
        else:
            size = {0xC1: 1, 0xC2: 2, 0xC3: 4, 0xC4: 8}[tag]
            index = int.from_bytes(data[pos:pos + size], "little")
            pos += size
        return objects[index], pos, objects
    if 0xD0 <= tag <= 0xDF:
        count = tag - 0xD0 if tag < 0xDF else None
        items = []
        if count is None:
            while pos < len(data) and data[pos] != 0x03:
                item, pos, objects = _opack_decode(data, pos, objects)
                items.append(item)
            pos += 1
        else:
            for _ in range(count):
                item, pos, objects = _opack_decode(data, pos, objects)
                items.append(item)
        return items, pos, objects
    if 0xE0 <= tag <= 0xEF:
        count = tag - 0xE0 if tag < 0xEF else None
        result = {}
        if count is None:
            while pos < len(data) and data[pos] != 0x03:
                key, pos, objects = _opack_decode(data, pos, objects)
                item, pos, objects = _opack_decode(data, pos, objects)
                result[key] = item
            pos += 1
        else:
            for _ in range(count):
                key, pos, objects = _opack_decode(data, pos, objects)
                item, pos, objects = _opack_decode(data, pos, objects)
                result[key] = item
        return result, pos, objects
    raise ValueError("unsupported OPACK tag 0x%02x" % tag)


def _remember(objects, value):
    if value not in objects:
        objects.append(value)
    return value


def _opack_read_len(data, pos, tag, inline, u8, u16, u32, u64):
    if inline <= tag < u8:
        return tag - inline, pos
    size = {u8: 1, u16: 2, u32: 4, u64: 8}[tag]
    return int.from_bytes(data[pos:pos + size], "little"), pos + size

# --- host identity / pairing record ----------------------------------------


class HostIdentity:
    def __init__(self, private_key, identifier, alt_irk):
        self.private_key = private_key
        self.identifier = identifier
        self.alt_irk = alt_irk

    @property
    def public_key(self):
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @classmethod
    def generate(cls):
        import uuid
        return cls(Ed25519PrivateKey.generate(), str(uuid.uuid4()).upper(),
                   secrets.token_bytes(16))

    @classmethod
    def load_or_create(cls, path):
        try:
            with open(path, "rb") as handle:
                data = plistlib.load(handle)
            private = Ed25519PrivateKey.from_private_bytes(data["private_key"])
            return cls(private, data["identifier"], data["alt_irk"])
        except (OSError, KeyError, ValueError, plistlib.InvalidFileException):
            identity = cls.generate()
            identity.save(path)
            return identity

    def save(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {
            "private_key": self.private_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()),
            "identifier": self.identifier,
            "alt_irk": self.alt_irk,
        }
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            plistlib.dump(data, handle)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


def siphash24(key, data):
    """SipHash-2-4 (public-domain algorithm), returns a u64."""
    if len(key) != 16:
        raise ValueError("SipHash key must be 16 bytes")
    mask = (1 << 64) - 1
    k0, k1 = struct.unpack("<QQ", key)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    def rotl(value, bits):
        return ((value << bits) | (value >> (64 - bits))) & mask

    def sip_round():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & mask
        v1 = rotl(v1, 13)
        v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & mask
        v3 = rotl(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & mask
        v3 = rotl(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & mask
        v1 = rotl(v1, 17)
        v1 ^= v2
        v2 = rotl(v2, 32)

    length = len(data)
    end = length - (length % 8)
    for offset in range(0, end, 8):
        m = struct.unpack_from("<Q", data, offset)[0]
        v3 ^= m
        sip_round()
        sip_round()
        v0 ^= m
    last = (length & 0xFF) << 56
    for index in range(length - end):
        last |= data[end + index] << (8 * index)
    v3 ^= last
    sip_round()
    sip_round()
    v0 ^= last
    v2 ^= 0xFF
    for _ in range(4):
        sip_round()
    return (v0 ^ v1 ^ v2 ^ v3) & mask


def auth_tag(alt_irk, identifier):
    output = struct.pack("<Q", siphash24(alt_irk, identifier.encode()))
    return bytes(output[5 - index] for index in range(6))


def mdns_txt(identity, name="BariSign", model="Mac17,7"):
    return {
        "name": name,
        "identifier": identity.identifier,
        "authTag": base64.b64encode(auth_tag(identity.alt_irk, identity.identifier)).decode(),
        "model": model,
        "flags": "1",
        "ver": "26",
        "minVer": "17",
    }

# --- the responder ----------------------------------------------------------


class PairingError(Exception):
    pass


class PairingRecord:
    def __init__(self, identity, peer):
        self.identity = identity
        self.peer = peer

    def as_dict(self):
        return {
            "public_key": self.identity.public_key,
            "private_key": self.identity.private_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()),
            "identifier": self.identity.identifier,
            "alt_irk": self.identity.alt_irk,
            "remote_unlock_host_key": "",
            "host_identifier": self.identity.identifier,
            "host_alt_irk": self.identity.alt_irk,
            "peer_alt_irk": self.peer.get("alt_irk", b""),
            "peer_udid": self.peer.get("udid", ""),
            "peer_model": self.peer.get("model", ""),
            "peer_name": self.peer.get("name", ""),
        }

    def write(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            plistlib.dump(self.as_dict(), handle)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


class PairableHost:
    """One device-initiated pairing conversation over an open TCP stream."""

    def __init__(self, reader, writer, identity, name="BariSign", model="Mac17,7",
                 log=None):
        self.reader = reader
        self.writer = writer
        self.identity = identity
        self.name = name
        self.model = model
        self.sequence = 0
        self.peer = {}
        self._log = log or (lambda text: None)
        self._frames = 0

    def _describe(self, value):
        try:
            message = value.get("message", {}).get("plain", {}).get("_0", value)
            if "request" in message:
                inner = message["request"].get("_0", {})
                if "handshake" in inner:
                    hs = inner["handshake"].get("_0", {})
                    return "handshake req wire=%r verify=%r" % (
                        hs.get("wireProtocolVersion"), hs.get("hostOptions"))
                return "request %s" % sorted(inner)
            if "response" in message:
                return "response %s" % sorted(message["response"])
            if "event" in message:
                event = message["event"].get("_0", {})
                if "pairingData" in event:
                    raw = event["pairingData"].get("_0", {})
                    data = raw.get("data", "")
                    try:
                        import json as _json
                        _ = _json
                        decoded = tlv_decode(__import__("base64").b64decode(data))
                        kinds = sorted(
                            "%d:%dB" % (kind, len(val)) for kind, val in decoded.items())
                        return "pairingData kind=%s state=%r kinds=%s" % (
                            raw.get("kind"), decoded.get(6), ",".join(kinds))
                    except Exception:                           # noqa: BLE001
                        return "pairingData kind=%s (%dB, undecodable)" % (
                            raw.get("kind"), len(data))
                return "event %s" % sorted(event)
            return "keys=%s" % sorted(message) if isinstance(message, dict) else type(message).__name__
        except Exception:                                       # noqa: BLE001
            return type(value).__name__

    async def _send(self, value):
        envelope = {
            "message": {"plain": {"_0": value}},
            "originatedBy": "device",
            "sequenceNumber": self.sequence,
        }
        self._log("TX seq=%d %s" % (self.sequence, self._describe(envelope)))
        self._write_frame(envelope)
        self.sequence += 1
        await self.writer.drain()

    def _write_frame(self, envelope):
        import json
        body = json.dumps(envelope).encode()
        self.writer.write(b"RPPairing" + struct.pack(">H", len(body)) + body)

    async def _recv(self):
        import json
        magic = await self.reader.readexactly(len(b"RPPairing"))
        if magic != b"RPPairing":
            raise PairingError("the device did not send an RPPairing frame")
        length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        body = await self.reader.readexactly(length)
        self._frames += 1
        try:
            envelope = json.loads(body)
        except Exception as exc:                                # noqa: BLE001
            self._log("RX frame %d: %d bytes, NOT JSON (%s): %r" % (
                self._frames, len(body), exc, body[:120]))
            raise PairingError("the device sent a non-JSON frame")
        try:
            value = envelope["message"]["plain"]["_0"]
        except (KeyError, TypeError):
            self._log("RX frame %d: unexpected envelope keys: %r" % (
                self._frames, str(body[:200])))
            raise PairingError("unexpected pairing envelope")
        self._log("RX frame %d: %s" % (self._frames, self._describe(envelope)))
        return value

    async def accept(self, pin_callback=None):
        await self._handshake()
        await self._pair_setup(pin_callback)
        return self.peer

    async def _handshake(self):
        request = await self._recv()
        try:
            handshake = request["request"]["_0"]["handshake"]["_0"]
        except (KeyError, TypeError):
            raise PairingError("the device sent an unexpected handshake")
        if handshake.get("hostOptions", {}).get("attemptPairVerify"):
            raise PairingError("the device already knows this host; use pair-verify instead")
        await self._send({
            "response": {
                "forRequestIdentifier": 0,
                "_1": {
                    "handshake": {
                        "_0": {
                            "wireProtocolVersion": 26,
                            "minimumSupportedWireProtocolVersion": 8,
                            "deviceOptions": {
                                "allowsPairSetup": True,
                                "allowsPinlessPairing": False,
                                "allowsIncomingTunnelConnections": False,
                                "allowsUpgradeOfLockdownPairings": False,
                                "allowsSharingSensitiveInfo": False,
                            },
                            "peerDeviceInfo": {
                                "udid": "",
                                "deviceKVSIncludesSensitiveInfo": False,
                                "identifier": self.identity.identifier,
                                "name": self.name,
                                "model": self.model,
                            },
                        }
                    }
                },
            }
        })

    async def _send_pairing_data(self, data, start_new_session=False, kind="setupManualPairing"):
        await self._send({
            "event": {
                "_0": {
                    "pairingData": {
                        "_0": {
                            "data": base64.b64encode(data).decode(),
                            "startNewSession": start_new_session,
                            "kind": kind,
                        }
                    }
                }
            }
        })

    async def _recv_pairing_data(self):
        response = await self._recv()
        event = response.get("event", {}).get("_0", {})
        if "pairingData" in event:
            return base64.b64decode(event["pairingData"]["_0"]["data"])
        if "pairingRejectedWithError" in event:
            raise PairingError("the target rejected the pairing")
        raise PairingError("the device sent no pairing data")

    async def _pair_setup(self, pin_callback):
        m1 = tlv_decode(await self._recv_pairing_data())
        _expect_state(m1, 1)

        salt = secrets.token_bytes(16)
        pin = "%06d" % secrets.randbelow(1000000)
        server = SrpServer(pin, salt)
        while len(server.public_bytes()) != 384:
            server = SrpServer(pin, salt)
        if pin_callback is not None:
            pin_callback(pin)
        entries = [(TLV_STATE, b"\x02"), (TLV_SALT, salt), (TLV_PUBLIC_KEY, server.public_bytes())]
        await self._send_pairing_data(tlv_encode(entries))

        m3 = tlv_decode(await self._recv_pairing_data())
        _no_error(m3)
        _expect_state(m3, 3)
        client_public = m3.get(TLV_PUBLIC_KEY)
        client_proof = m3.get(TLV_PROOF)
        if not client_public or not client_proof:
            raise PairingError("pair-setup M3 is missing the public key or proof")
        server.process(client_public)
        if not server.verify(client_proof):
            await self._send_pairing_data(tlv_encode([(TLV_STATE, b"\x04"), (TLV_ERROR, b"\x02")]))
            raise PairingError("the pairing code did not match")
        session_key = server.key
        await self._send_pairing_data(tlv_encode([(TLV_STATE, b"\x04"), (TLV_PROOF, server.proof)]))

        setup_key = HKDF(algorithm=hashes.SHA512(), length=32,
                         salt=b"Pair-Setup-Encrypt-Salt",
                         info=b"Pair-Setup-Encrypt-Info").derive(session_key)
        cipher = ChaCha20Poly1305(setup_key)

        m5 = tlv_decode(await self._recv_pairing_data())
        _no_error(m5)
        _expect_state(m5, 5)
        try:
            plaintext = cipher.decrypt(b"\x00\x00\x00\x00PS-Msg05", m5[TLV_ENCRYPTED_DATA], b"")
        except Exception as exc:                                # noqa: BLE001
            raise PairingError("cannot decrypt the target identity: %s" % exc)
        device_tlv = tlv_decode(plaintext)
        info = opack_decode(device_tlv[TLV_INFO])
        self.peer = {
            "alt_irk": info.get("altIRK", b""),
            "udid": info.get("remotepairing_udid", ""),
            "model": info.get("model", ""),
            "name": info.get("name", ""),
            "identifier": info.get("accountID", ""),
        }

        m6_plain = self._accessory_identity(session_key)
        encrypted = cipher.encrypt(b"\x00\x00\x00\x00PS-Msg06", m6_plain, b"")
        await self._send_pairing_data(tlv_encode([(TLV_ENCRYPTED_DATA, encrypted), (TLV_STATE, b"\x06")]))

    def _accessory_identity(self, session_key):
        accessory_x = HKDF(algorithm=hashes.SHA512(), length=32,
                           salt=b"Pair-Setup-Accessory-Sign-Salt",
                           info=b"Pair-Setup-Accessory-Sign-Info").derive(session_key)
        public = self.identity.public_key
        signbuf = accessory_x + self.identity.identifier.encode() + public
        signature = self.identity.private_key.sign(signbuf)
        info = opack_encode({
            "altIRK": self.identity.alt_irk,
            "btAddr": "11:22:33:44:55:66",
            "mac": b"\x11\x22\x33\x44\x55\x66",
            "remotepairing_serial_number": "AAAAAAAAAAAA",
            "accountID": self.identity.identifier,
            "remotepairing_udid": "",
            "model": self.model,
            "name": self.name,
        })
        return tlv_encode([
            (TLV_IDENTIFIER, self.identity.identifier.encode()),
            (TLV_PUBLIC_KEY, public),
            (TLV_SIGNATURE, signature),
            (TLV_INFO, info),
        ])


def _expect_state(tlv, state):
    value = tlv.get(TLV_STATE)
    if not value or value[0] != state:
        raise PairingError("pair-setup steps arrived out of order")


def _no_error(tlv):
    if TLV_ERROR in tlv:
        raise PairingError("the target reported pairing error %d" % tlv[TLV_ERROR][0])
