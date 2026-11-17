#!/usr/bin/env python3
# =============================================================================
#  BariStore — Clean-Room Apple Authentication & Developer Portal (MIT)
#
#  Implements:
#    * TLS trust setup for a-Shell (Mozilla CA bundle + pinned Apple Root CA)
#    * Anisette v3 (with WebSocket provisioning) and v1 client
#    * Apple GrandSlam (GSA) SRP-6a (2048-bit, PBKDF2-SHA256, AES-CBC, AES-GCM)
#    * Two-factor authentication (Trusted Device & SMS)
#    * Apple Developer Portal (developerservices2.apple.com) client:
#      teams, devices, development certificates, App IDs, App Groups, profiles
#
#  Clean-room MIT implementation built on Python stdlib + `cryptography`.
#  Protocol reference: nab138/isideload (MIT) and jkcoxson/idevice (MIT).
# =============================================================================

import base64
import binascii
import concurrent.futures
import gzip
import hashlib
import hmac
import http.client
import json
import os
import plistlib
import re
import secrets
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from . import storage

MACHINE_NAME = "BariStore"

GSA_URL_BAG = "https://gsa.apple.com/grandslam/GsService2/lookup"
DEV_HOST = "developerservices2.apple.com"
DEV_CLIENT_ID = "XABBG36SBA"
DEV_PROTOCOL = "QH65B2"

GSA_CLIENT_INFO = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
GSA_MAC_CLIENT_INFO = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
GSA_USER_AGENT = "akd/1.0 CFNetwork/808.1.4"

ANISETTE_LIST_URL = "https://servers.sidestore.io/servers.json"
DEFAULT_ANISETTE_SERVERS = [
    "https://mac-ani.jkcoxson.com",
    "https://ani.jkcoxson.com",
    "https://ani.sidestore.io",
    "https://ani.sidestore.app",
    "https://ani.sidestore.zip",
    "https://ani.846969.xyz",
    "https://ani.npeg.us",
    "https://anisette.wedotstud.io",
]

# RFC 5054 2048-bit group for Apple GrandSlam SRP-6a
SRP_N = int(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    16,
)
SRP_G = 2

APPLE_ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"


class AppleAuthError(Exception):
    pass


class PortalError(AppleAuthError):
    def __init__(self, code, message):
        super().__init__("Apple developer portal error %d: %s" % (code, message))
        self.code = int(code)
        self.message = message


class CertLimitReachedError(PortalError):
    def __init__(self, certs):
        super().__init__(7460, "Maximum number of development certificates reached.")
        self.certs = certs


class AppIdLimitReachedError(PortalError):
    def __init__(self, identifier, existing_app_ids):
        super().__init__(
            7313,
            "No free App ID slots remaining for %s (free accounts allow 10 App IDs per 7 days)."
            % identifier,
        )
        self.identifier = identifier
        self.existing_app_ids = existing_app_ids


# --- TLS Trust Configuration ------------------------------------------------

def _find_trust_file(filename):
    for base in (
        os.path.join(storage.ROOT, "third_party", "apple-roots"),
        os.path.join(storage.ROOT, "third_party", "ca-bundle"),
        storage.ROOT,
        storage.HERE,
    ):
        candidate = os.path.join(base, filename)
        if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
            return os.path.abspath(candidate)
    return None


SSL_CTX = ssl.create_default_context()
try:
    SSL_CTX.set_alpn_protocols(["http/1.1"])
except NotImplementedError:
    pass

CA_BUNDLE_PATH = _find_trust_file("cacert.pem")
APPLE_ROOT_PATH = _find_trust_file("apple-roots.pem")

try:
    import certifi
    if certifi.where() and os.path.isfile(certifi.where()):
        SSL_CTX.load_verify_locations(certifi.where())
except Exception:
    pass

if CA_BUNDLE_PATH:
    try:
        SSL_CTX.load_verify_locations(CA_BUNDLE_PATH)
    except Exception:
        pass

_LOGIN_STEP_LOCK = threading.Lock()
_LOGIN_STEP_TEXT = ""
_APPLE_CTX = None


def set_login_step(text):
    global _LOGIN_STEP_TEXT
    with _LOGIN_STEP_LOCK:
        _LOGIN_STEP_TEXT = str(text or "")


def get_login_step():
    with _LOGIN_STEP_LOCK:
        return _LOGIN_STEP_TEXT


def is_apple_host(host):
    return bool(host) and (host == "apple.com" or host.endswith(".apple.com"))


def ssl_context_for(host):
    global _APPLE_CTX
    if APPLE_ROOT_PATH and is_apple_host(host):
        if _APPLE_CTX is None:
            ctx = ssl.create_default_context()
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass
            if CA_BUNDLE_PATH:
                try:
                    ctx.load_verify_locations(CA_BUNDLE_PATH)
                except Exception:
                    pass
            ctx.load_verify_locations(APPLE_ROOT_PATH)
            _APPLE_CTX = ctx
        return _APPLE_CTX
    return SSL_CTX


def _getaddrinfo_bounded(host, port, timeout=8):
    """getaddrinfo with a hard deadline (system DNS can stall under VPN)."""
    box = {}

    def _run():
        try:
            box["v4"] = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        except Exception:
            box["v4"] = None
        try:
            box["v6"] = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
        except Exception:
            box["v6"] = None

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(max(1.0, float(timeout)))
    v4 = box.get("v4")
    v6 = box.get("v6")
    if v4 and v6:
        return v4 + v6
    if v4:
        return v4
    if v6:
        return v6
    raise socket.gaierror("DNS lookup timed out for %s" % host)


def _connect_preferred_ipv4(host, port, timeout):
    """Connect TCP socket preferring IPv4 first (avoids IPv6 blackholes on iOS/LocalDevVPN)."""
    try:
        infos = _getaddrinfo_bounded(host, port)
    except Exception as exc:
        raise AppleAuthError("DNS lookup failed for %s: %s" % (host, exc))
    if not infos:
        raise AppleAuthError("No DNS records found for %s" % host)
    # Sort AF_INET (IPv4) ahead of AF_INET6 so stalled IPv6 routes don't block for full timeout
    infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    last_err = None
    per_addr_timeout = min(float(timeout), 6.0) if len(infos) > 1 else float(timeout)
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(per_addr_timeout)
            sock.connect(sockaddr)
            sock.settimeout(float(timeout))
            return sock
        except Exception as exc:
            last_err = exc
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise last_err or AppleAuthError("Could not connect to %s:%s" % (host, port))


class _IPv4PreferredHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        raw = _connect_preferred_ipv4(self.host, self.port, self.timeout or 20)
        if self._tunnel_host:
            self.sock = raw
            self._tunnel()
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _IPv4PreferredHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = _connect_preferred_ipv4(self.host, self.port, self.timeout or 20)


def http_request(method, url, headers=None, body=None, timeout=20, redirects=5):
    """Perform an HTTP/HTTPS request preserving exact header casing and preferring IPv4."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    if not host:
        raise AppleAuthError("Invalid URL: %s" % url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    if parts.scheme == "https":
        conn = _IPv4PreferredHTTPSConnection(
            host, port, timeout=timeout, context=ssl_context_for(host)
        )
    else:
        conn = _IPv4PreferredHTTPConnection(host, port, timeout=timeout)

    if isinstance(body, str):
        body = body.encode("utf-8")

    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", parts.netloc)
        sent = set()
        for key, value in (headers or {}).items():
            conn.putheader(key, value)
            sent.add(key.lower())
        if body is not None and "content-length" not in sent:
            conn.putheader("Content-Length", str(len(body)))
        if "accept-encoding" not in sent:
            conn.putheader("Accept-Encoding", "identity")
        conn.endheaders(body)
        response = conn.getresponse()
        data = response.read()
        status = response.status
        got = {k.lower(): v for k, v in response.getheaders()}
        if got.get("content-encoding", "").lower() == "gzip":
            data = gzip.decompress(data)
    finally:
        conn.close()

    if status in (301, 302, 303, 307, 308) and redirects > 0 and got.get("location"):
        target = urllib.parse.urljoin(url, got["location"])
        if status == 303 or (status in (301, 302) and method == "POST"):
            method, body = "GET", None
        return http_request(method, target, headers, body, timeout, redirects - 1)

    return status, got, data


# --- Symmetric Crypto Helpers (via `cryptography`) --------------------------

def aes_cbc_decrypt(key, iv, data):
    """AES-CBC decrypt and strip PKCS#7 padding."""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = decryptor.update(data) + decryptor.finalize()
    if out:
        pad = out[-1]
        if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad):
            out = out[:-pad]
    return out


def aes_gcm_decrypt(key, nonce, ciphertext, aad, tag):
    """AES-256-GCM decrypt (supports 12-byte and 16-byte GrandSlam nonces)."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except Exception as exc:
        raise AppleAuthError("App token failed authentication check: %s" % exc)


def loads_bare_plist(data):
    data = data.strip()
    if data.startswith(b"<dict"):
        data = b'<plist version="1.0">' + data + b"</plist>"
    return plistlib.loads(data)


# --- GrandSlam SRP-6a Client ------------------------------------------------

def _trim_int(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def _pad_bytes(value_bytes, width):
    return value_bytes.rjust(width, b"\x00")


def _sha256(*chunks):
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def srp_password_key(password, salt, iterations, protocol):
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        digest = binascii.hexlify(digest)
    elif protocol != "s2k":
        raise AppleAuthError("Unsupported Apple SRP protocol: %s" % protocol)
    return hashlib.pbkdf2_hmac("sha256", digest, salt, iterations, 32)


class SrpClient:
    def __init__(self):
        self.n_bytes = _trim_int(SRP_N)
        self.width = len(self.n_bytes)
        self.a = int.from_bytes(secrets.token_bytes(32), "big")
        self.a_pub = _trim_int(pow(SRP_G, self.a, SRP_N))
        self.premaster = b""
        self.session_key = b""
        self.m1 = b""
        self.m2 = b""

    def process(self, username, password_key, salt, b_pub_bytes):
        b_pub = int.from_bytes(b_pub_bytes, "big")
        if b_pub % SRP_N == 0:
            raise AppleAuthError("Apple returned an invalid SRP parameter (B = 0).")
        g_bytes = _trim_int(SRP_G)
        u = int.from_bytes(
            _sha256(_pad_bytes(self.a_pub, self.width), _pad_bytes(b_pub_bytes, self.width)),
            "big",
        )
        k = int.from_bytes(_sha256(self.n_bytes, _pad_bytes(g_bytes, self.width)), "big")
        identity_hash = _sha256(b"", b":", password_key)
        x = int.from_bytes(_sha256(salt, identity_hash), "big")

        premaster = pow(b_pub - k * pow(SRP_G, x, SRP_N), self.a + u * x, SRP_N)
        self.premaster = _trim_int(premaster)
        self.session_key = _sha256(self.premaster)

        n_xor_g = bytes(
            a ^ b
            for a, b in zip(
                _sha256(self.n_bytes), _sha256(_pad_bytes(g_bytes, self.width))
            )
        )
        self.m1 = _sha256(
            n_xor_g,
            _sha256(username.encode("utf-8")),
            salt,
            self.a_pub,
            b_pub_bytes,
            self.session_key,
        )
        self.m2 = _sha256(self.a_pub, self.m1, self.session_key)
        return self.m1

    def verify(self, server_m2):
        return hmac.compare_digest(self.m2, server_m2)

    def decrypt_spd(self, blob):
        errors = []
        for label, base in (("H(S)", self.session_key), ("S", self.premaster)):
            key = hmac.new(base, b"extra data key:", hashlib.sha256).digest()
            iv = hmac.new(base, b"extra data iv:", hashlib.sha256).digest()[:16]
            try:
                return loads_bare_plist(aes_cbc_decrypt(key, iv, blob))
            except Exception as exc:
                errors.append("%s: %s" % (label, exc))
        raise AppleAuthError("Could not decrypt Apple sign-in response (%s)." % "; ".join(errors))


# --- Minimal RFC 6455 WebSocket for Anisette v3 Provisioning ----------------

class _WebSocket:
    def __init__(self, url, timeout=12):
        parts = urllib.parse.urlsplit(url)
        secure = parts.scheme == "wss"
        port = parts.port or (443 if secure else 80)
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")

        raw = _connect_preferred_ipv4(parts.hostname, port, timeout=timeout)
        self.sock = (
            ssl_context_for(parts.hostname).wrap_socket(raw, server_hostname=parts.hostname)
            if secure
            else raw
        )
        self.sock.settimeout(float(timeout))
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        handshake = (
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
            % (path, parts.netloc, nonce)
        )
        self.sock.sendall(handshake.encode())
        self.buffer = b""
        while b"\r\n\r\n" not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise AppleAuthError("Anisette provisioning socket closed during handshake.")
            self.buffer += chunk
        head, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise AppleAuthError(
                "Anisette server refused provisioning socket: %s"
                % head.split(b"\r\n")[0].decode("utf-8", "replace")
            )

    def _recv_exactly(self, count):
        while len(self.buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AppleAuthError("Anisette provisioning socket closed unexpectedly.")
            self.buffer += chunk
        head, self.buffer = self.buffer[:count], self.buffer[count:]
        return head

    def recv(self):
        while True:
            header = self._recv_exactly(2)
            opcode = header[0] & 0x0F
            masked = header[1] & 0x80
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv_exactly(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv_exactly(8))[0]
            mask = self._recv_exactly(4) if masked else None
            payload = self._recv_exactly(length) if length else b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode in (0x1, 0x2):
                return payload.decode("utf-8", "replace")

    def _send_frame(self, opcode, payload):
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = secrets.token_bytes(4)
        header += mask
        header += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header))

    def send_json(self, payload):
        self._send_frame(0x1, json.dumps(payload).encode())

    def close(self):
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# --- Anisette Client --------------------------------------------------------

class AnisetteClient:
    def __init__(self, url, state_path=None):
        self.url = url.rstrip("/")
        self.state_path = state_path or storage.ANISETTE_STATE_FILE
        self.version = None
        self.client_info = GSA_CLIENT_INFO
        self.user_agent = GSA_USER_AGENT
        self.routing_info = "0"
        self.identifier = None
        self.adi_pb = None
        self._load()

    def _load(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                saved = json.load(handle)
            self.identifier = base64.b64decode(saved["identifier"])
            if saved.get("adi_pb"):
                self.adi_pb = base64.b64decode(saved["adi_pb"])
        except Exception:
            self.identifier = secrets.token_bytes(16)

    def _save(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        payload = {"identifier": base64.b64encode(self.identifier).decode()}
        if self.adi_pb:
            payload["adi_pb"] = base64.b64encode(self.adi_pb).decode()
        with open(self.state_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            pass

    @property
    def device_id(self):
        return str(uuid.UUID(bytes=self.identifier))

    @property
    def md_lu(self):
        return hashlib.sha256(self.identifier).hexdigest()

    def detect(self):
        status, _, body = http_request("GET", self.url + "/v3/client_info", timeout=6)
        if status == 200:
            try:
                payload = json.loads(body)
            except ValueError:
                payload = {}
            if isinstance(payload, dict) and "client_info" in payload and "user_agent" in payload:
                self.version = 3
                info = payload.get("client_info")
                agent = payload.get("user_agent")
                if isinstance(info, str) and info.strip():
                    self.client_info = info.strip()
                if isinstance(agent, str) and agent.strip():
                    self.user_agent = agent.strip()
                return 3

        status, _, body = http_request("GET", self.url + "/", timeout=6)
        if status == 200:
            try:
                payload = json.loads(body)
            except ValueError:
                payload = {}
            if "X-Apple-I-MD" in payload:
                self.version = 1
                return 1

        raise AppleAuthError("%s is not a valid Anisette server." % self.url)

    def needs_provisioning(self):
        return self.version == 3 and not self.adi_pb

    def forget_provisioning(self):
        self.adi_pb = None
        self.identifier = secrets.token_bytes(16)
        self._save()

    def provision(self, gs):
        ws_url = self.url.replace("https://", "wss://").replace("http://", "ws://")
        sock = _WebSocket(ws_url + "/v3/provisioning_session")
        headers = {"X-Apple-I-MD-LU": self.md_lu, "X-Mme-Device-Id": self.device_id}
        try:
            while True:
                message = sock.recv()
                if message is None:
                    raise AppleAuthError("Anisette provisioning socket closed prematurely.")
                payload = json.loads(message)
                result = payload.get("result")
                if result == "GiveIdentifier":
                    sock.send_json({"identifier": base64.b64encode(self.identifier).decode()})
                elif result == "GiveStartProvisioningData":
                    response = gs.plist_request(
                        gs.url("midStartProvisioning"),
                        {"Header": {}, "Request": {}},
                        extra_headers=headers,
                    )
                    sock.send_json({"spim": response["spim"]})
                elif result == "GiveEndProvisioningData":
                    response = gs.plist_request(
                        gs.url("midFinishProvisioning"),
                        {"Header": {}, "Request": {"cpim": payload["cpim"]}},
                        extra_headers=headers,
                    )
                    sock.send_json({"ptm": response["ptm"], "tk": response["tk"]})
                elif result == "ProvisioningSuccess":
                    self.adi_pb = base64.b64decode(payload["adi_pb"])
                    self._save()
                    return
                else:
                    raise AppleAuthError(
                        "Anisette provisioning failed: %s"
                        % payload.get("message", result or message)
                    )
        finally:
            sock.close()

    def headers(self):
        if self.version == 1:
            status, _, body = http_request("GET", self.url + "/", timeout=10)
            if status != 200:
                raise AppleAuthError("Anisette server returned HTTP %d." % status)
            payload = json.loads(body)
            self.routing_info = payload.get("X-Apple-I-MD-RINFO", "0")
            return {
                "X-Mme-Device-Id": payload.get("X-Mme-Device-Id", self.device_id),
                "X-Apple-I-MD": payload["X-Apple-I-MD"],
                "X-Apple-I-MD-M": payload["X-Apple-I-MD-M"],
            }

        status, _, body = http_request(
            "POST",
            self.url + "/v3/get_headers",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {
                    "identifier": base64.b64encode(self.identifier).decode(),
                    "adi_pb": base64.b64encode(self.adi_pb).decode(),
                }
            ),
            timeout=10,
        )
        payload = json.loads(body) if body else {}
        if status != 200 or payload.get("result") != "Headers":
            raise AppleAuthError(
                "Anisette server refused to mint headers: %s"
                % payload.get("message", "HTTP %d" % status)
            )
        self.routing_info = payload.get("X-Apple-I-MD-RINFO", "0")
        return {
            "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-MD": payload["X-Apple-I-MD"],
            "X-Apple-I-MD-M": payload["X-Apple-I-MD-M"],
        }

    def client_provided_data(self):
        cpd = {
            "bootstrap": "true",
            "icscrec": "true",
            "loc": "en_US",
            "pbe": "false",
            "prkgen": "true",
            "svct": "iCloud",
        }
        cpd.update(self.headers())
        return cpd


# --- GrandSlam Service ------------------------------------------------------

_CACHED_URL_BAG = None
_CACHED_URL_BAG_AT = 0


def _fetch_gsa_url_bag(headers):
    global _CACHED_URL_BAG, _CACHED_URL_BAG_AT
    now = time.time()
    if _CACHED_URL_BAG and (now - _CACHED_URL_BAG_AT < 900):
        return _CACHED_URL_BAG
    status, _, body = http_request("GET", GSA_URL_BAG, headers=headers, timeout=12)
    if status != 200:
        raise AppleAuthError("Could not reach Apple's GrandSlam service (HTTP %d)." % status)
    _CACHED_URL_BAG = plistlib.loads(body)["urls"]
    _CACHED_URL_BAG_AT = now
    return _CACHED_URL_BAG


class GrandSlam:
    def __init__(self, anisette):
        self.anisette = anisette
        self.url_bag = _fetch_gsa_url_bag(self.mac_headers())

    def base_headers(self, plist=True):
        headers = {}
        if plist:
            headers["Content-Type"] = "text/x-xml-plist"
            headers["Accept"] = "text/x-xml-plist"
        headers["X-Mme-Client-Info"] = self.anisette.client_info
        headers["User-Agent"] = self.anisette.user_agent
        headers["X-Xcode-Version"] = "14.2 (14C18)"
        headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
        return headers

    def mac_headers(self, plist=True):
        headers = self.base_headers(plist)
        info = self.anisette.client_info
        if "mac" in info.lower():
            headers["X-Mme-Client-Info"] = info
        else:
            headers["X-Mme-Client-Info"] = GSA_MAC_CLIENT_INFO
        return headers

    def url(self, key):
        if key not in self.url_bag:
            raise AppleAuthError("Apple's URL bag has no '%s' entry." % key)
        value = self.url_bag[key]
        host = urllib.parse.urlsplit(value).hostname or ""
        if not is_apple_host(host):
            raise AppleAuthError(
                "Apple's URL bag pointed '%s' at %r (not an apple.com host). Refusing."
                % (key, host)
            )
        return value

    def plist_request(self, url, body, extra_headers=None):
        target = urllib.parse.urlsplit(url).hostname or ""
        if not is_apple_host(target):
            raise AppleAuthError("Refusing to send authenticated Apple request to %r." % target)
        headers = self.base_headers()
        headers.update(extra_headers or {})
        payload = plistlib.dumps(body, fmt=plistlib.FMT_XML)
        status, _, response = http_request("POST", url, headers=headers, body=payload)
        if status != 200:
            snippet = " ".join((response or b"").decode("utf-8", "replace").split())[:240]
            raise AppleAuthError(
                "Apple returned HTTP %d for %s.%s"
                % (status, url, (" Said: " + snippet) if snippet else "")
            )
        parsed = plistlib.loads(response)
        if "Response" not in parsed:
            raise AppleAuthError("Unexpected reply from Apple (no Response section).")
        return check_gs_error(parsed["Response"])


def check_gs_error(response):
    status = response.get("Status", response)
    code = status.get("ec", 0)
    if code:
        raise AppleAuthError(
            "Apple rejected the request (%s): %s" % (code, status.get("em", "no message"))
        )
    return response


def anisette_Order(preferred=""):
    """Return ordered list of HTTPS Anisette URLs to try."""
    saved_pref = preferred or storage.load_state().get("anisette_url") or ""
    candidates = []
    if saved_pref:
        candidates.append(saved_pref)
    candidates.extend(DEFAULT_ANISETTE_SERVERS)
    seen = set()
    order = []
    for url in candidates:
        clean = (url or "").strip().rstrip("/")
        if clean.startswith("https://") and clean not in seen:
            seen.add(clean)
            order.append(clean)
    return order[:8]


def _fast_ordered_anisette(preferred=""):
    """Probe candidate Anisette servers concurrently and return responsive ones fastest-first."""
    candidates = anisette_Order(preferred)
    if len(candidates) <= 1:
        return candidates

    def _probe(idx_url):
        idx, url = idx_url
        t0 = time.time()
        try:
            st, _, body = http_request("GET", url + "/v3/client_info", timeout=4)
            if st == 200 and b"client_info" in (body or b""):
                return (0 if idx == 0 and preferred else 1, time.time() - t0, url)
        except Exception:
            pass
        try:
            st, _, body = http_request("GET", url + "/", timeout=4)
            if st == 200 and b"X-Apple-I-MD" in (body or b""):
                return (0 if idx == 0 and preferred else 1, time.time() - t0, url)
        except Exception:
            pass
        return (2, 999.0 + idx, url)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(candidates)) as pool:
            scored = list(pool.map(_probe, enumerate(candidates), timeout=5))
        scored.sort(key=lambda item: (item[0], item[1]))
        return [item[2] for item in scored]
    except Exception:
        return candidates


_PROVISIONING_ERROR_MARKERS = (
    "anisette",
    "provisioning",
    "adi_pb",
    "-45061",
    "-45062",
    "mint headers",
    "refused to mint",
    "not a valid anisette",
    "provisioning socket",
)


def _is_provisioning_error(message):
    """Only these errors mean the provisioned machine identity is actually bad."""
    low = str(message or "").lower()
    return any(marker in low for marker in _PROVISIONING_ERROR_MARKERS)


def connect_anisette(preferred_url="", state_path=None):
    """Connect and provision an Anisette server, with automatic failover."""
    state_path = state_path or storage.ANISETTE_STATE_FILE
    tried = []
    for url in _fast_ordered_anisette(preferred_url):
        host = urllib.parse.urlsplit(url).hostname or url
        try:
            set_login_step("Connecting to Anisette (%s)…" % host)
            anisette = AnisetteClient(url, state_path)
            anisette.detect()
            gs = GrandSlam(anisette)
            if anisette.needs_provisioning():
                set_login_step("Provisioning Anisette (%s)…" % host)
                anisette.provision(gs)
            try:
                anisette.headers()
            except AppleAuthError as exc:
                # Only rotate the machine when the identity itself is rejected.
                # A network blip must NOT burn the machine the saved session was
                # issued for — that is what made tokens look "expired" forever.
                if not _is_provisioning_error(exc):
                    raise
                anisette.forget_provisioning()
                set_login_step("Re-provisioning Anisette (%s)…" % host)
                anisette.provision(gs)
                anisette.headers()
            return anisette, gs
        except Exception as exc:
            tried.append("%s (%s)" % (host, exc))
    raise AppleAuthError("No Anisette server responded. Tried: " + "; ".join(tried[:4]))


# --- Apple Account & Session Management -------------------------------------

def _is_identity_refused(message):
    text = str(message).lower()
    return (
        "503" in text
        or "service unavailable" in text
        or "-80045" in text
        or "-80046" in text
        or "cannot be completed at this time" in text
    )


class AppleAccount:
    def __init__(self, email, gs, anisette):
        self.email = email
        self.gs = gs
        self.anisette = anisette
        self.spd = None

    def login_step(self, password):
        """Run one SRP-6a authentication round.

        Returns:
          - "ok" if authenticated without 2FA (or after 2FA verification)
          - "device-2fa" if a trusted-device 2FA code needs to be requested & verified
          - "device-2fa-sent" if a trusted-device 2FA code was already pushed
          - "sms-2fa" if an SMS 2FA code is required
        """
        cpd = self.anisette.client_provided_data()
        srp = SrpClient()
        first = self.gs.plist_request(
            self.gs.url("gsService"),
            {
                "Header": {"Version": "1.0.1"},
                "Request": {
                    "A2k": srp.a_pub,
                    "cpd": cpd,
                    "o": "init",
                    "ps": ["s2k", "s2k_fo"],
                    "u": self.email,
                },
            },
        )
        password_key = srp_password_key(
            password, bytes(first["s"]), int(first["i"]), first["sp"]
        )
        proof = srp.process(
            self.email, password_key, bytes(first["s"]), bytes(first["B"])
        )
        second = self.gs.plist_request(
            self.gs.url("gsService"),
            {
                "Header": {"Version": "1.0.1"},
                "Request": {
                    "M1": proof,
                    "c": first["c"],
                    "cpd": cpd,
                    "o": "complete",
                    "u": self.email,
                },
            },
            extra_headers={"Connection": "close"},
        )
        if not srp.verify(bytes(second["M2"])):
            raise AppleAuthError("Apple's server proof did not verify.")

        self.spd = srp.decrypt_spd(bytes(second["spd"]))
        status = second.get("Status", {})
        au = status.get("au")
        if au == "trustedDeviceSecondaryAuth":
            return "device-2fa"
        if au == "secondaryAuth":
            return "sms-2fa"
        if au is None and status.get("hsc") == 409:
            return "device-2fa-sent"
        if au == "repair" or au is None:
            return "ok"
        if self._pet():
            return "ok"
        raise AppleAuthError(
            "Apple requires an additional sign-in action (%s). Sign in once at https://appleid.apple.com in Safari, then retry."
            % au
        )

    def _pet(self):
        try:
            return self.spd["t"]["com.apple.gs.idms.pet"]["token"]
        except (KeyError, TypeError):
            return None

    def _identity_headers(self):
        headers = self.anisette.headers()
        identity = "%s:%s" % (self.spd["adsid"], self.spd["GsIdmsToken"])
        headers["X-Apple-Identity-Token"] = base64.b64encode(identity.encode()).decode()
        headers["X-Apple-I-MD-RINFO"] = self.anisette.routing_info
        return headers

    def request_2fa_code(self, mode):
        if mode == "device-2fa":
            headers = self.gs.mac_headers()
            headers.update(self._identity_headers())
            status, _, _ = http_request(
                "GET", self.gs.url("trustedDeviceSecondaryAuth"), headers=headers
            )
            if status >= 400:
                raise AppleAuthError("Apple could not send a 2FA code (HTTP %d)." % status)
        elif mode == "sms-2fa":
            headers = self.gs.mac_headers(plist=False)
            headers.update(self._identity_headers())
            status, _, _ = http_request(
                "GET", self.gs.url("secondaryAuth"), headers=headers
            )
            if status >= 400:
                raise AppleAuthError("Apple could not send an SMS 2FA code (HTTP %d)." % status)

    def submit_2fa_code(self, mode, code):
        code = "".join(ch for ch in str(code or "") if ch.isdigit())
        if len(code) < 6:
            raise AppleAuthError("Please enter the 6-digit verification code.")
        if mode == "sms-2fa":
            headers = self.gs.mac_headers(plist=False)
            headers.update(self._identity_headers())
            headers["Content-Type"] = "application/json"
            headers["Accept"] = "application/json, text/javascript, */*; q=0.01"
            status, _, body = http_request(
                "POST",
                "https://gsa.apple.com/auth/verify/phone/securitycode",
                headers=headers,
                body=json.dumps(
                    {
                        "securityCode": {"code": code},
                        "phoneNumber": {"id": 1},
                        "mode": "sms",
                    }
                ),
            )
            if status >= 400:
                raise AppleAuthError("Apple rejected the SMS verification code.")
        else:
            headers = self.gs.base_headers()
            headers.update(self._identity_headers())
            headers["security-code"] = code
            status, _, body = http_request(
                "GET", self.gs.url("validateCode"), headers=headers
            )
            if status >= 400:
                raise AppleAuthError("Apple rejected the verification code (HTTP %d)." % status)
            check_gs_error(plistlib.loads(body))

    def app_token(self, app="xcode.auth"):
        if not app.startswith("com.apple.gs."):
            app = "com.apple.gs." + app
        adsid = self.spd["adsid"]
        session_key = bytes(self.spd["sk"])
        checksum = hmac.new(session_key, digestmod=hashlib.sha256)
        checksum.update(b"apptokens")
        checksum.update(adsid.encode())
        checksum.update(app.encode())

        response = self.gs.plist_request(
            self.gs.url("gsService"),
            {
                "Header": {"Version": "1.0.1"},
                "Request": {
                    "app": [app],
                    "c": self.spd["c"],
                    "checksum": checksum.digest(),
                    "cpd": self.anisette.client_provided_data(),
                    "o": "apptokens",
                    "u": adsid,
                    "t": self.spd["GsIdmsToken"],
                },
            },
        )
        blob = bytes(response["et"])
        if len(blob) < 35 or blob[:3] != b"XYZ":
            raise AppleAuthError("App token returned in an unrecognized format.")
        decrypted = aes_gcm_decrypt(
            session_key, blob[3:19], blob[19:-16], blob[:3], blob[-16:]
        )
        token = loads_bare_plist(decrypted)
        if token.get("status-code") != 200:
            raise AppleAuthError(
                "Apple refused the developer token (status %s)." % token.get("status-code")
            )
        return token["t"][app]["token"], adsid


# --- Developer Portal Session & Operations ----------------------------------

def dev_url(endpoint, device_type="ios/"):
    return "https://%s/services/%s/%s%s.action?clientId=%s" % (
        DEV_HOST,
        DEV_PROTOCOL,
        device_type,
        endpoint,
        DEV_CLIENT_ID,
    )


class DeveloperSession:
    def __init__(self, account, token, adsid):
        self.account = account
        self.gs = account.gs
        self.anisette = account.anisette
        self.token = token
        self.adsid = adsid

    def headers(self):
        headers = self.gs.base_headers()
        headers.update(self.anisette.headers())
        headers["X-Apple-GS-Token"] = self.token
        headers["X-Apple-I-Identity-Id"] = self.adsid
        return headers

    def call(self, endpoint, body=None, key=None, device_type="ios/"):
        payload = {
            "clientId": DEV_CLIENT_ID,
            "protocolVersion": DEV_PROTOCOL,
            "requestId": str(uuid.uuid4()).upper(),
            "userLocale": ["en_US"],
        }
        payload.update(body or {})
        url = dev_url(endpoint, device_type)
        status, _, raw = http_request(
            "POST",
            url,
            headers=self.headers(),
            body=plistlib.dumps(payload, fmt=plistlib.FMT_XML),
        )
        if status != 200:
            raise AppleAuthError(
                "Developer portal returned HTTP %d for %s." % (status, endpoint)
            )
        response = plistlib.loads(raw)
        code = response.get("resultCode", 0)
        if code:
            message = (
                response.get("userString")
                or response.get("resultString")
                or "no message"
            )
            raise PortalError(int(code), message)
        if key is not None:
            if key not in response:
                raise AppleAuthError(
                    "Developer portal reply for %s had no '%s'." % (endpoint, key)
                )
            return response[key]
        return response


_LAST_SESSION_ERROR = ""


def get_last_session_error():
    return _LAST_SESSION_ERROR


def get_saved_session():
    """Return a validated DeveloperSession from saved state, or None if expired/missing.

    A single transient portal/network failure is retried with a freshly minted
    set of Anisette headers *on the same machine identity*. Only a real auth
    rejection is treated as an expired session.
    """
    global _LAST_SESSION_ERROR
    _LAST_SESSION_ERROR = ""
    state = storage.load_state()
    email = (state.get("email") or "").strip()
    saved = state.get("gs_token") or {}
    if not email or not isinstance(saved, dict):
        _LAST_SESSION_ERROR = "No Apple ID is saved on this device."
        return None
    if (saved.get("email") or "").lower() != email.lower():
        _LAST_SESSION_ERROR = "The saved Apple ID does not match the current account."
        return None
    token = saved.get("token") or ""
    adsid = saved.get("adsid") or ""
    if not token or not adsid:
        _LAST_SESSION_ERROR = "No developer token is saved — sign in again."
        return None
    for attempt in range(2):
        try:
            anisette, gs = connect_anisette()
            session = DeveloperSession(AppleAccount(email, gs, anisette), token, adsid)
            teams = session.call("listTeams", key="teams", device_type="")
            if teams and not state.get("team_id"):
                storage.update_state(
                    team_id=teams[0].get("teamId", ""),
                    team_name=teams[0].get("name", ""),
                )
            return session
        except Exception as exc:
            _LAST_SESSION_ERROR = str(exc)
            if attempt == 0:
                time.sleep(1)
                continue
    return None


_PENDING_LOGINS = {}


_FATAL_AUTH_ERROR_CODES = (
    "-22406",
    "-20970",
    "-20101",
    "-20209",
    "-22421",
    "-20283",
)
_FATAL_AUTH_SUBSTRINGS = (
    "correct password",
    "entered incorrectly",
    "account is locked",
    "locked for security",
    "not an apple id",
    "invalid apple id",
    "no developer team",
    "additional sign-in action",
)


def _is_fatal_credential_error(msg):
    low = str(msg or "").lower()
    if any(code in low for code in _FATAL_AUTH_ERROR_CODES):
        return True
    return any(sub in low for sub in _FATAL_AUTH_SUBSTRINGS)


def start_apple_login(email, password, preferred_anisette=""):
    """Begin Apple ID login.

    Returns either:
      - {"status": "authenticated", "email": ..., "team_id": ..., "team_name": ..., "teams": [...]}
      - {"status": "2fa_required", "login_id": ..., "mode": "device-2fa"|"sms-2fa", "message": ...}
    """
    email = (email or "").strip()
    if not email or not password:
        raise AppleAuthError("Apple ID and password are required.")

    set_login_step("Finding fastest Anisette server…")
    candidates = _fast_ordered_anisette(preferred_anisette)
    last_error = None
    tried = []

    try:
        for idx, url in enumerate(candidates, 1):
            host = urllib.parse.urlsplit(url).hostname or url
            try:
                set_login_step("(%d/%d) Connecting to Anisette (%s)…" % (idx, len(candidates), host))
                anisette = AnisetteClient(url, storage.ANISETTE_STATE_FILE)
                anisette.detect()
                set_login_step("(%d/%d) Contacting Apple GrandSlam via %s…" % (idx, len(candidates), host))
                gs = GrandSlam(anisette)
                if anisette.needs_provisioning():
                    set_login_step("(%d/%d) Provisioning Anisette machine on %s…" % (idx, len(candidates), host))
                    anisette.provision(gs)
                try:
                    set_login_step("(%d/%d) Minting Anisette headers from %s…" % (idx, len(candidates), host))
                    anisette.headers()
                except AppleAuthError as exc:
                    if not _is_provisioning_error(exc):
                        raise
                    anisette.forget_provisioning()
                    set_login_step("(%d/%d) Re-provisioning Anisette on %s…" % (idx, len(candidates), host))
                    anisette.provision(gs)
                    anisette.headers()

                set_login_step("Authenticating Apple ID (SRP-6a) via %s…" % host)
                account = AppleAccount(email, gs, anisette)
                step = account.login_step(password)
                if step == "ok":
                    set_login_step("Fetching Apple Developer team…")
                    return _finalize_login(account, password)

                set_login_step("Requesting 2FA verification code…")
                account.request_2fa_code(step)
                login_id = secrets.token_hex(16)
                _PENDING_LOGINS[login_id] = {
                    "account": account,
                    "password": password,
                    "mode": step,
                    "created_at": time.time(),
                }
                return {
                    "status": "2fa_required",
                    "login_id": login_id,
                    "mode": step,
                    "message": (
                        "Enter the 6-digit verification code sent via SMS."
                        if step == "sms-2fa"
                        else "Enter the 6-digit verification code shown on your trusted device."
                    ),
                }
            except Exception as exc:
                last_error = exc
                msg = str(exc)
                if _is_fatal_credential_error(msg):
                    raise AppleAuthError(msg)
                tried.append("%s: %s" % (host, msg))
                if _is_provisioning_error(msg):
                    try:
                        anisette.forget_provisioning()
                    except Exception:
                        pass
                continue

        raise AppleAuthError(
            "Could not sign in with any Anisette server (%s)."
            % ("; ".join(tried[:3]) if tried else str(last_error))
        )
    finally:
        set_login_step("")


def verify_apple_2fa(login_id, code):
    """Complete 2FA verification for a pending Apple login."""
    pending = _PENDING_LOGINS.get(login_id)
    if not pending:
        raise AppleAuthError("Login session expired. Please sign in again.")
    account = pending["account"]
    password = pending["password"]
    mode = pending["mode"]

    account.submit_2fa_code(mode, code)
    step = account.login_step(password)
    if step != "ok" and not account._pet():
        raise AppleAuthError("Sign-in did not complete after 2FA (%s)." % step)
    _PENDING_LOGINS.pop(login_id, None)
    return _finalize_login(account, password)


def _finalize_login(account, _password):
    token, adsid = account.app_token("xcode.auth")
    session = DeveloperSession(account, token, adsid)
    teams = session.call("listTeams", key="teams", device_type="") or []
    if not teams:
        raise AppleAuthError(
            "This Apple account has no developer team. Sign in once at https://developer.apple.com in Safari to accept the free agreement."
        )
    saved_team_id = storage.load_state().get("team_id") or ""
    chosen_team = teams[0]
    for team in teams:
        if team.get("teamId") == saved_team_id:
            chosen_team = team
            break

    key_path = ensure_private_key(account.email)
    storage.update_state(
        email=account.email,
        team_id=chosen_team.get("teamId", ""),
        team_name=chosen_team.get("name", ""),
        key=key_path,
        gs_token={
            "email": account.email,
            "token": token,
            "adsid": adsid,
            "saved_at": int(time.time()),
        },
    )
    return {
        "status": "authenticated",
        "email": account.email,
        "team_id": chosen_team.get("teamId", ""),
        "team_name": chosen_team.get("name", ""),
        "teams": [
            {"id": t.get("teamId", ""), "name": t.get("name", ""), "type": t.get("type", "")}
            for t in teams
        ],
    }


# --- Portal Helpers (Devices, Keys, Certificates, App IDs, Profiles) --------

def _same_udid(one, other):
    strip = lambda v: "".join(ch for ch in str(v or "").lower() if ch in "0123456789abcdef")
    return strip(one) == strip(other)


def list_devices(session, team_id):
    return session.call("listDevices", {"teamId": team_id}, key="devices") or []


def ensure_device(session, team_id, udid, name="BariStore iPhone"):
    devices = list_devices(session, team_id)
    if any(_same_udid(d.get("deviceNumber"), udid) for d in devices):
        return
    try:
        session.call(
            "addDevice",
            {"teamId": team_id, "name": name, "deviceNumber": udid},
            key="device",
        )
    except PortalError as exc:
        if exc.code == 35:
            return
        raise


def private_key_path(email):
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    return os.path.join(storage.STATE_DIR, digest, "key.pem")


def ensure_private_key(email):
    path = private_key_path(email)
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(path, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _load_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def _hex_modulus(modulus):
    data = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")
    return ":".join("%02X" % byte for byte in data)


def _make_csr(key):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Cupertino"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BariStore"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "BariStore"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def list_ios_certs(session, team_id):
    certs = session.call(
        "listAllDevelopmentCerts", {"teamId": team_id}, key="certificates"
    )
    result = []
    for cert in certs or []:
        platform = (
            cert.get("certificatePlatform")
            or (cert.get("certificateType") or {}).get("platform")
            or "ios"
        )
        if str(platform).lower() == "ios":
            result.append(cert)
    return result


def revoke_certificate(session, team_id, serial_number):
    session.call(
        "revokeDevelopmentCert",
        {"teamId": team_id, "serialNumber": serial_number},
    )
    return True


def obtain_certificate(session, team_id, key_path, workdir=None, revoke_serial=None):
    """Obtain or reuse a matching development certificate for `key_path`."""
    workdir = workdir or storage.STATE_DIR
    cert_der = os.path.join(workdir, "cert.der")
    cert_pem = os.path.join(workdir, "cert.pem")
    key = _load_key(key_path)
    mine = _hex_modulus(key.private_numbers().public_numbers.n)

    if revoke_serial:
        revoke_certificate(session, team_id, revoke_serial)

    existing = list_ios_certs(session, team_id)
    for cert in existing:
        if not cert.get("certContent"):
            continue
        try:
            loaded = x509.load_der_x509_certificate(bytes(cert["certContent"]))
            if _hex_modulus(loaded.public_key().public_numbers().n) == mine:
                with open(cert_der, "wb") as handle:
                    handle.write(bytes(cert["certContent"]))
                with open(cert_pem, "wb") as handle:
                    handle.write(loaded.public_bytes(serialization.Encoding.PEM))
                return cert_pem, True
        except Exception:
            continue

    csr = _make_csr(key)
    try:
        result = session.call(
            "submitDevelopmentCSR",
            {
                "teamId": team_id,
                "csrContent": csr,
                "machineName": MACHINE_NAME,
                "machineId": str(uuid.uuid4()).upper(),
            },
            key="certRequest",
        )
    except PortalError as exc:
        if exc.code == 7460:
            # Auto-revoke oldest BariStore cert if present, otherwise ask user
            for cert in existing:
                mname = (cert.get("machineName") or "").lower()
                if mname == "baristore" and cert.get("serialNumber"):
                    revoke_certificate(session, team_id, cert["serialNumber"])
                    result = session.call(
                        "submitDevelopmentCSR",
                        {
                            "teamId": team_id,
                            "csrContent": csr,
                            "machineName": MACHINE_NAME,
                            "machineId": str(uuid.uuid4()).upper(),
                        },
                        key="certRequest",
                    )
                    break
            else:
                raise CertLimitReachedError(
                    [
                        {
                            "serial": c.get("serialNumber", ""),
                            "name": c.get("name") or c.get("machineName") or "Certificate",
                            "machine": c.get("machineName") or "Unknown",
                            "expires": str(c.get("expirationDate") or ""),
                        }
                        for c in existing
                        if c.get("serialNumber")
                    ]
                )
        else:
            raise

    request_id = result["certRequestId"]
    for cert in list_ios_certs(session, team_id):
        if cert.get("certificateId") == request_id and cert.get("certContent"):
            raw_der = bytes(cert["certContent"])
            loaded = x509.load_der_x509_certificate(raw_der)
            with open(cert_der, "wb") as handle:
                handle.write(raw_der)
            with open(cert_pem, "wb") as handle:
                handle.write(loaded.public_bytes(serialization.Encoding.PEM))
            return cert_pem, False

    raise AppleAuthError("Apple issued a certificate but did not return its content.")


def list_app_ids(session, team_id):
    listing = session.call("listAppIds", {"teamId": team_id})
    app_ids = listing.get("appIds") or []
    available = listing.get("availableQuantity")
    max_qty = listing.get("maxQuantity", 10)
    return app_ids, available, max_qty


def ensure_app_id(session, team_id, identifier, name):
    app_ids, available, _max_qty = list_app_ids(session, team_id)
    for app_id in app_ids:
        if app_id.get("identifier") == identifier:
            return app_id
    if available is not None and available <= 0:
        raise AppIdLimitReachedError(identifier, app_ids)
    clean_name = re.sub(r"[^A-Za-z0-9 ]", " ", name or "BariStore App").strip() or "BariStore App"
    try:
        return session.call(
            "addAppId",
            {"teamId": team_id, "identifier": identifier, "name": clean_name[:60]},
            key="appId",
        )
    except PortalError as exc:
        if exc.code in (7313, 9412) or "maximum" in exc.message.lower() or "limit" in exc.message.lower():
            raise AppIdLimitReachedError(identifier, app_ids)
        raise


def group_identifier_for(team_id, full_bundle_id, base_bundle_id=""):
    base = (base_bundle_id or full_bundle_id or "").split(".Beta")[0]
    for prefix in (
        "com.SideStore.SideStore",
        "com.kdt.livecontainer",
        "com.rileytestut.AltStore",
    ):
        if base == prefix or base.startswith(prefix + "."):
            if base.startswith("com.kdt.livecontainer"):
                return "group.com.SideStore.SideStore." + team_id
            return "group." + (full_bundle_id or base_bundle_id)
    return ""


def ensure_app_group(session, team_id, app_id_dict, group_id, name):
    try:
        groups = (
            session.call(
                "listApplicationGroups",
                {"teamId": team_id},
                key="applicationGroupList",
            )
            or []
        )
    except Exception:
        return ""
    application_group = ""
    for group in groups:
        if isinstance(group, dict) and (
            group.get("identifier") == group_id
            or group.get("applicationGroup") == group_id
        ):
            application_group = group.get("applicationGroup") or group_id
            break
    else:
        try:
            clean_name = re.sub(r"[^A-Za-z0-9 ]", " ", name or "BariStore Group").strip() or "BariStore Group"
            created = session.call(
                "addApplicationGroup",
                {"teamId": team_id, "name": clean_name[:60], "identifier": group_id},
                key="applicationGroup",
            )
            application_group = (created or {}).get("applicationGroup") or group_id
        except Exception:
            return ""
    try:
        session.call(
            "updateAppId",
            {"teamId": team_id, "appIdId": app_id_dict["appIdId"], "APG3427HIY": True},
            key="appId",
        )
        session.call(
            "assignApplicationGroupToAppId",
            {
                "teamId": team_id,
                "applicationGroups": application_group,
                "appIdId": app_id_dict["appIdId"],
            },
        )
    except Exception:
        return ""
    return application_group


def download_profile(session, team_id, app_id_dict):
    profile = session.call(
        "downloadTeamProvisioningProfile",
        {"teamId": team_id, "appIdId": app_id_dict["appIdId"]},
        key="provisioningProfile",
    )
    return bytes(profile["encodedProfile"])


def provision_for_signing(
    session,
    email,
    udid,
    base_bundle_id,
    app_name,
    team_id="",
    revoke_serial=None,
    reuse_full_bundle_id="",
    progress=None,
):
    """Register device, obtain key+cert, register App ID (+ group), and download profile."""
    report = progress or (lambda _msg: None)
    if not team_id:
        report("Reading Apple Developer teams…")
        teams = session.call("listTeams", key="teams", device_type="") or []
        if not teams:
            raise AppleAuthError("No developer team found on this Apple ID.")
        team_id = teams[0]["teamId"]

    report("Registering device with Apple…")
    ensure_device(session, team_id, udid, "BariStore Device")
    key_path = ensure_private_key(email)
    report("Preparing development certificate…")
    cert_path, cert_reused = obtain_certificate(
        session, team_id, key_path, storage.STATE_DIR, revoke_serial=revoke_serial
    )

    if reuse_full_bundle_id:
        full_bundle_id = reuse_full_bundle_id
    else:
        suffix = "." + team_id
        full_bundle_id = (
            base_bundle_id
            if base_bundle_id.endswith(suffix)
            else (base_bundle_id + suffix)
        )

    report("Registering App ID %s…" % full_bundle_id)
    app_id = ensure_app_id(session, team_id, full_bundle_id, app_name)
    group_id = group_identifier_for(team_id, full_bundle_id, base_bundle_id)
    if group_id:
        report("Configuring App Group…")
        ensure_app_group(session, team_id, app_id, group_id, app_name)

    report("Downloading provisioning profile…")
    profile_bytes = download_profile(session, team_id, app_id)
    profile_path = os.path.join(
        storage.STATE_DIR, "profile-%s.mobileprovision" % full_bundle_id
    )
    with open(profile_path, "wb") as handle:
        handle.write(profile_bytes)
    # Also write default profile.mobileprovision for backward compatibility
    default_profile = os.path.join(storage.STATE_DIR, "profile.mobileprovision")
    with open(default_profile, "wb") as handle:
        handle.write(profile_bytes)

    storage.update_state(
        email=email,
        udid=udid,
        team_id=team_id,
        key=key_path,
        cert=cert_path,
        profile=profile_path,
    )
    return {
        "team_id": team_id,
        "bundle_id": full_bundle_id,
        "key": key_path,
        "cert": cert_path,
        "cert_reused": cert_reused,
        "profile": profile_path,
    }


def run_network_diagnostics():
    """Probe DNS, TCP, TLS, and HTTP for GitHub, Apple GSA, and Anisette servers."""
    targets = [
        ("github", "https://raw.githubusercontent.com/"),
        ("apple", "https://gsa.apple.com/"),
    ]
    for url in anisette_Order()[:4]:
        targets.append(("anisette", url))

    results = []
    for kind, url in targets:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        port = parts.port or 443
        entry = {"kind": kind, "host": host, "ok": False, "detail": ""}
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            ip = infos[0][4][0]
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(8)
            try:
                probe.connect((ip, port))
                ctx = ssl_context_for(host)
                tls = ctx.wrap_socket(probe, server_hostname=host)
                version = tls.version()
                tls.close()
            finally:
                probe.close()
            if kind == "anisette":
                status, _, _ = http_request("GET", url.rstrip("/") + "/v3/client_info", timeout=12)
                entry["ok"] = status == 200
                entry["detail"] = "%s · HTTP %d" % (version, status)
            else:
                entry["ok"] = True
                entry["detail"] = "%s · %s" % (ip, version)
        except Exception as exc:
            entry["detail"] = str(exc)[:120]
        results.append(entry)
    return results
