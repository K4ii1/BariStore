#!/usr/bin/env python3
# =============================================================================
#  BariSign — minimal TLS 1.2 PSK client (MIT)
#
#  The RPPairing tunnel on iOS is a TLS 1.2 *pre-shared key* connection with no
#  certificates and no key exchange: the PSK is the 32-byte X25519 shared secret
#  produced by pair-verify.  iOS picks one of two CBC suites, so only those two
#  are offered and implemented:
#
#      0x00AF  TLS_PSK_WITH_AES_256_CBC_SHA384
#      0x008C  TLS_PSK_WITH_AES_128_CBC_SHA
#
#  This is enough of RFC 5246 for that one ciphersuite pair.  It uses only
#  primitives that a-Shell's cryptography 3.4.8 already ships (AES-CBC, HMAC,
#  SHA-256/SHA-384); no sslpsk, no OpenSSL PSK callbacks, no native modules.
#
#  Reference (read, not copied): jkcoxson/idevice, remote_pairing/tls_psk.rs
#  (MIT).  Wire format: RFC 5246, RFC 4279 (PSK), RFC 7366 (not used).
#
#  UNTESTED ON A DEVICE.  Tested on Linux against OpenSSL s_server in
#  tests/test_tls_psk.py.
# =============================================================================

import hashlib
import hmac as std_hmac
import os
import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TLS_VERSION = b"\x03\x03"
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_SERVER_KEY_EXCHANGE = 12
HS_SERVER_HELLO_DONE = 14
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20

MAX_PLAINTEXT = 16384

# (id, key_len, mac_len, prf_hash, mac_hash)
SUITES = {
    0x00AF: (32, 48, hashes.SHA384(), hashes.SHA384()),
    0x008C: (16, 20, hashes.SHA256(), hashes.SHA1()),
}
PREFERRED = (0x00AF, 0x008C)


class TlsPskError(Exception):
    pass


def _hmac(hash_algorithm, key, data):
    mac = hmac.HMAC(key, hash_algorithm)
    mac.update(data)
    return mac.finalize()


def _p_hash(hash_algorithm, secret, seed, length):
    """TLS 1.2 P_hash (RFC 5246 section 5)."""
    out = b""
    a = _hmac(hash_algorithm, secret, seed)
    while len(out) < length:
        out += _hmac(hash_algorithm, secret, a + seed)
        a = _hmac(hash_algorithm, secret, a)
    return out[:length]


def _prf(hash_algorithm, secret, label, seed, length):
    return _p_hash(hash_algorithm, secret, label + seed, length)


def _psk_premaster(psk):
    """RFC 4279 section 2: other_secret is all zeroes for a pure-PSK suite."""
    n = len(psk)
    return struct.pack(">H", n) + b"\x00" * n + struct.pack(">H", n) + psk


def _padding(len_):
    return (4 - (len_ % 4)) % 4


class TlsPskStream:
    """An asyncio-like reader/writer over a TLS 1.2 PSK connection."""

    def __init__(self, reader, writer, suite, master, keys):
        self._reader = reader
        self._writer = writer
        self._suite = suite
        self._master = master
        self._client_mac, self._server_mac, self._client_key, self._server_key = keys
        self._write_seq = 0          # 0 is the encrypted Finished
        self._read_seq = 0           # 0 is the server Finished
        self._inbuf = b""
        self._closed = False

    # -- low-level records ---------------------------------------------------
    async def _read_raw_record(self):
        header = await self._reader.readexactly(5)
        ctype = header[0]
        length = struct.unpack(">H", header[3:5])[0]
        payload = await self._reader.readexactly(length)
        return ctype, payload

    def _record_header(self, ctype, length):
        return bytes([ctype]) + TLS_VERSION + struct.pack(">H", length)

    def _encrypt_record(self, ctype, plaintext):
        key_len, mac_len, prf_hash, mac_hash = SUITES[self._suite]
        seq = struct.pack(">Q", self._write_seq)
        mac_input = seq + bytes([ctype]) + TLS_VERSION + struct.pack(">H", len(plaintext)) + plaintext
        mac = _hmac(mac_hash, self._client_mac, mac_input)
        payload = plaintext + mac
        pad_len = 16 - (len(payload) % 16)
        payload += bytes([pad_len - 1]) * pad_len
        iv = os.urandom(16)
        enc = Cipher(algorithms.AES(self._client_key), modes.CBC(iv)).encryptor()
        ciphertext = enc.update(payload) + enc.finalize()
        self._write_seq += 1
        body = iv + ciphertext
        return self._record_header(ctype, len(body)) + body

    def _decrypt_record(self, ctype, body):
        key_len, mac_len, prf_hash, mac_hash = SUITES[self._suite]
        if len(body) < 16 + 16:
            raise TlsPskError("TLS record too short")
        iv, ciphertext = body[:16], body[16:]
        if len(ciphertext) % 16:
            raise TlsPskError("TLS record is not block aligned")
        dec = Cipher(algorithms.AES(self._server_key), modes.CBC(iv)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        pad = padded[-1] + 1
        if pad > len(padded) or pad > 256:
            raise TlsPskError("bad TLS padding")
        if any(byte != pad - 1 for byte in padded[-pad:]):
            raise TlsPskError("bad TLS padding bytes")
        data = padded[:-pad]
        if len(data) < mac_len:
            raise TlsPskError("TLS record too short for its MAC")
        plaintext, received = data[:-mac_len], data[-mac_len:]
        seq = struct.pack(">Q", self._read_seq)
        mac_input = seq + bytes([ctype]) + TLS_VERSION + struct.pack(">H", len(plaintext)) + plaintext
        expected = _hmac(mac_hash, self._server_mac, mac_input)
        if not std_hmac.compare_digest(received, expected):
            raise TlsPskError("TLS record MAC verification failed")
        self._read_seq += 1
        return plaintext

    # -- handshake -----------------------------------------------------------
    @classmethod
    async def connect(cls, reader, writer, psk):
        client_random = os.urandom(32)
        body = bytearray()
        body += TLS_VERSION
        body += client_random
        body += b"\x00"                      # empty session id
        suites = b"".join(struct.pack(">H", s) for s in PREFERRED)
        body += struct.pack(">H", len(suites)) + suites
        body += b"\x01\x00"                  # null compression only
        hello = b"\x01" + struct.pack(">I", len(body))[1:] + bytes(body)
        writer.write(bytes([CT_HANDSHAKE]) + TLS_VERSION + struct.pack(">H", len(hello)) + hello)
        await writer.drain()

        transcript = bytearray(hello)
        server_random = None
        suite = None
        server_done = False
        while not server_done:
            ctype, payload = await cls._read_raw_record_static(reader)
            if ctype == CT_ALERT:
                raise TlsPskError("TLS alert during handshake: %s" % _alert_text(payload))
            if ctype != CT_HANDSHAKE:
                raise TlsPskError("expected a handshake record, got content type %d" % ctype)
            transcript += payload
            offset = 0
            while offset + 4 <= len(payload):
                msg_type = payload[offset]
                msg_len = int.from_bytes(payload[offset + 1:offset + 4], "big")
                msg = payload[offset:offset + 4 + msg_len]
                if msg_type == HS_SERVER_HELLO:
                    if len(msg) < 4 + 2 + 32 + 1:
                        raise TlsPskError("short ServerHello")
                    server_random = msg[6:38]
                    sid_len = msg[38]
                    pos = 39 + sid_len
                    if len(msg) < pos + 3:
                        raise TlsPskError("short ServerHello cipher field")
                    suite = struct.unpack(">H", msg[pos:pos + 2])[0]
                elif msg_type == HS_SERVER_HELLO_DONE:
                    server_done = True
                elif msg_type == HS_SERVER_KEY_EXCHANGE:
                    pass                      # PSK identity hint: irrelevant to us
                offset += 4 + msg_len
        if server_random is None or suite is None:
            raise TlsPskError("server did not send a usable ServerHello")
        if suite not in SUITES:
            raise TlsPskError(
                "the device selected cipher 0x%04X; this client implements 0x00AF and 0x008C only" % suite)

        key_len, mac_len, prf_hash, mac_hash = SUITES[suite]
        premaster = _psk_premaster(psk)
        master = _prf(prf_hash, premaster, b"master secret", client_random + server_random, 48)
        block = _prf(prf_hash, master, b"key expansion", server_random + client_random,
                     mac_len * 2 + key_len * 2)
        client_mac = block[:mac_len]
        server_mac = block[mac_len:mac_len * 2]
        client_key = block[mac_len * 2:mac_len * 2 + key_len]
        server_key = block[mac_len * 2 + key_len:mac_len * 2 + key_len * 2]

        client_key_exchange = b"\x10\x00\x00\x02\x00\x00"   # empty PSK identity
        transcript += client_key_exchange
        writer.write(bytes([CT_HANDSHAKE]) + TLS_VERSION
                     + struct.pack(">H", len(client_key_exchange)) + client_key_exchange)
        writer.write(bytes([CT_CHANGE_CIPHER_SPEC]) + TLS_VERSION + b"\x00\x01\x01")

        verify = _prf(prf_hash, master, b"client finished",
                      hashlib.new(_hash_name(prf_hash), bytes(transcript)).digest(), 12)
        finished = b"\x14" + b"\x00\x00\x0c" + verify
        stream = cls(reader, writer, suite, master, (client_mac, server_mac, client_key, server_key))
        writer.write(stream._encrypt_record(CT_HANDSHAKE, finished))
        stream._write_seq = 1        # 0 was the encrypted Finished
        await writer.drain()
        transcript += finished

        # Server ChangeCipherSpec, then its encrypted Finished.
        server_finished_ok = False
        while not server_finished_ok:
            ctype, payload = await cls._read_raw_record_static(reader)
            if ctype == CT_ALERT:
                raise TlsPskError("TLS alert after Finished: %s" % _alert_text(payload))
            if ctype == CT_CHANGE_CIPHER_SPEC:
                continue
            if ctype not in (CT_HANDSHAKE, CT_APPLICATION_DATA):
                continue
            plaintext = stream._decrypt_record(ctype, payload)
            if plaintext[:1] != b"\x14":
                # NewSessionTicket or similar: ignore, keep reading.
                continue
            expected = _prf(prf_hash, master, b"server finished",
                            hashlib.new(_hash_name(prf_hash), bytes(transcript)).digest(), 12)
            received = plaintext[4:16]
            if not std_hmac.compare_digest(received, expected):
                raise TlsPskError("server Finished verification failed")
            server_finished_ok = True
        return stream

    @staticmethod
    async def _read_raw_record_static(reader):
        header = await reader.readexactly(5)
        return header[0], await reader.readexactly(struct.unpack(">H", header[3:5])[0])

    # -- application data ----------------------------------------------------
    async def _fill(self):
        while True:
            ctype, payload = await self._read_raw_record()
            if ctype == CT_ALERT:
                text = _alert_text(payload)
                self._closed = True
                raise ConnectionError("TLS alert: %s" % text)
            if ctype == CT_CHANGE_CIPHER_SPEC:
                continue
            if ctype in (CT_HANDSHAKE, CT_APPLICATION_DATA):
                plaintext = self._decrypt_record(ctype, payload)
                if ctype == CT_HANDSHAKE or not plaintext:
                    continue
                self._inbuf += plaintext
                return

    async def readexactly(self, size):
        while len(self._inbuf) < size:
            await self._fill()
        data, self._inbuf = self._inbuf[:size], self._inbuf[size:]
        return data

    async def read(self, size=-1):
        if not self._inbuf:
            await self._fill()
        if size is None or size < 0:
            data, self._inbuf = self._inbuf, b""
            return data
        data, self._inbuf = self._inbuf[:size], self._inbuf[size:]
        return data

    def write(self, data):
        for offset in range(0, len(data), MAX_PLAINTEXT):
            chunk = data[offset:offset + MAX_PLAINTEXT]
            self._writer.write(self._encrypt_record(CT_APPLICATION_DATA, chunk))

    async def drain(self):
        await self._writer.drain()

    def close(self):
        self._closed = True
        try:
            self._writer.close()
        except Exception:                                          # noqa: BLE001
            pass

    async def wait_closed(self):
        try:
            await self._writer.wait_closed()
        except Exception:                                          # noqa: BLE001
            pass


def _hash_name(hash_algorithm):
    if hash_algorithm.name == "sha384":
        return "sha384"
    return "sha256"


_ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 40: "handshake_failure",
    47: "illegal_parameter", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 90: "user_canceled", 112: "unrecognized_name",
}


def _alert_text(payload):
    if len(payload) < 2:
        return "malformed alert"
    level = {1: "warning", 2: "fatal"}.get(payload[0], str(payload[0]))
    return "%s (%s)" % (_ALERTS.get(payload[1], "description %d" % payload[1]), level)


async def connect(reader, writer, psk):
    """Handshake and return a TlsPskStream wrapping an open TCP connection."""
    return await TlsPskStream.connect(reader, writer, psk)
