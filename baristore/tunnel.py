#!/usr/bin/env python3
# =============================================================================
#  BariStore — RPPairing Control Channel, TLS-PSK Tunnel & Session (MIT)
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

from . import mdns, pairing, remote_xpc, storage, tcp6, tls_psk

MAGIC = b"RPPairing"
CDTUNNEL = b"CDTunnel"
WIRE_VERSION = 19
LOOPBACK_HOST = "10.7.0.1"


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


def load_record(path=None):
    path = path or storage.RECORD_PATH
    with open(path, "rb") as handle:
        record = plistlib.load(handle)
    if record.get("host_identifier"):
        record["identifier"] = record["host_identifier"]
    for key in ("private_key", "public_key", "identifier"):
        if not record.get(key):
            raise PairingTunnelError("The pairing file is missing %s" % key)
    if len(record["private_key"]) == 64:
        record["private_key"] = bytes(record["private_key"])[:32]
    if not record.get("alt_irk") and record.get("host_alt_irk"):
        record["alt_irk"] = record["host_alt_irk"]
    return record


class RemotePairingLink:
    """RPPairing client over an open TCP stream."""

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
        self._write(
            {
                "message": {"plain": {"_0": value}},
                "originatedBy": "host",
                "sequenceNumber": self.sequence,
            }
        )
        self.sequence += 1
        await self.writer.drain()

    async def _recv_plain(self):
        magic = await self.reader.readexactly(len(MAGIC))
        if magic != MAGIC:
            raise PairingTunnelError("The device did not answer with RPPairing framing")
        length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        body = await self.reader.readexactly(length)
        envelope = json.loads(body)
        try:
            return envelope["message"]["plain"]["_0"]
        except (KeyError, TypeError):
            raise PairingTunnelError("Unexpected RPPairing envelope")

    async def pair_verify(self):
        key_bytes = bytes(self.record["private_key"])
        if len(key_bytes) == 64:
            key_bytes = key_bytes[:32]
        private = Ed25519PrivateKey.from_private_bytes(key_bytes)
        identifier = str(self.record["identifier"])
        ephemeral = X25519PrivateKey.generate()
        public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        await self._send_plain(
            {
                "request": {
                    "_0": {
                        "handshake": {
                            "_0": {
                                "hostOptions": {"attemptPairVerify": True},
                                "wireProtocolVersion": WIRE_VERSION,
                            }
                        }
                    }
                }
            }
        )
        response = await self._recv_plain()
        handshake = response.get("response", {}).get("_1", {}).get("handshake", {}).get("_0", {})
        peer = handshake.get("peerDeviceInfo", {})

        def send_pairing(data, new_session):
            self._write(
                {
                    "message": {
                        "plain": {
                            "_0": {
                                "event": {
                                    "_0": {
                                        "pairingData": {
                                            "_0": {
                                                "data": base64.b64encode(data).decode(),
                                                "startNewSession": new_session,
                                                "kind": "verifyManualPairing",
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "originatedBy": "host",
                    "sequenceNumber": self.sequence,
                }
            )
            self.sequence += 1

        async def receive_pairing():
            reply = await self._recv_plain()
            event = reply.get("event", {}).get("_0", {})
            if "pairingData" in event:
                return _tlv(base64.b64decode(event["pairingData"]["_0"]["data"]))
            raise PairingTunnelError("The device sent no pair-verify data")

        send_pairing(_tlv_encode([(6, b"\x01"), (3, public)]), True)
        await self.writer.drain()
        data = await receive_pairing()
        if 7 in data or 3 not in data:
            raise PairingTunnelError("Pair-verify was refused (pairing file may be expired or invalid)")
        peer_public = X25519PublicKey.from_public_bytes(data[3])
        shared = ephemeral.exchange(peer_public)
        self.psk = shared

        key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Verify-Encrypt-Salt",
            info=b"Pair-Verify-Encrypt-Info",
        ).derive(shared)
        cipher = ChaCha20Poly1305(key)
        signbuf = public + identifier.encode() + data[3]
        signature = private.sign(signbuf)
        encrypted = cipher.encrypt(
            b"\x00\x00\x00\x00PV-Msg03",
            _tlv_encode([(1, identifier.encode()), (10, signature)]),
            b"",
        )
        send_pairing(_tlv_encode([(6, b"\x03"), (5, encrypted)]), False)
        await self.writer.drain()
        result = await receive_pairing()
        if 7 in result:
            raise PairingTunnelError("Pair-verify failed: this device no longer recognizes the pairing record")

        client_key = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"ClientEncrypt-main"
        ).derive(shared)
        server_key = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"ServerEncrypt-main"
        ).derive(shared)
        self.client_cipher = ChaCha20Poly1305(client_key)
        self.server_cipher = ChaCha20Poly1305(server_key)
        self.peer = peer
        return peer

    async def encrypted_request(self, value):
        if self.client_cipher is None:
            raise PairingTunnelError("pair-verify has not completed")
        nonce = struct.pack("<Q", self.encrypted_sequence) + b"\x00" * 4
        ciphertext = self.client_cipher.encrypt(nonce, json.dumps(value).encode(), b"")
        self._write(
            {
                "message": {"streamEncrypted": {"_0": base64.b64encode(ciphertext).decode()}},
                "originatedBy": "host",
                "sequenceNumber": self.sequence,
            }
        )
        await self.writer.drain()
        self.encrypted_sequence += 1
        reply = await self._recv_plain_stream()
        encrypted = reply.get("message", {}).get("streamEncrypted", {}).get("_0")
        if encrypted is None:
            raise PairingTunnelError("The device sent no encrypted reply")
        plaintext = self.server_cipher.decrypt(nonce, base64.b64decode(encrypted), b"")
        decoded = json.loads(plaintext)
        response = decoded.get("response", {}).get("_1")
        if response is None:
            raise PairingTunnelError("The device refused the request: %r" % (decoded,))
        if "errorExtended" in response:
            raise PairingTunnelError(
                "The device refused the request: %r" % (response["errorExtended"],)
            )
        return response

    async def _recv_plain_stream(self):
        magic = await self.reader.readexactly(len(MAGIC))
        if magic != MAGIC:
            raise PairingTunnelError("bad RPPairing framing")
        length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        return json.loads(await self.reader.readexactly(length))

    async def create_tcp_listener(self):
        response = await self.encrypted_request(
            {
                "request": {
                    "_0": {
                        "createListener": {
                            "key": base64.b64encode(self.psk).decode(),
                            "transportProtocolType": "tcp",
                        }
                    }
                }
            }
        )
        listener = response.get("createListener") or {}
        port = listener.get("port")
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        if not isinstance(port, int):
            raise PairingTunnelError("The device did not return a tunnel port")
        return port


class TunnelLink:
    """Raw IPv6 packet link over the TLS-PSK CDTunnel stream."""

    def __init__(self, stream):
        self.stream = stream

    def send(self, packet):
        self.stream.write(packet)

    async def recv(self):
        header = await self.stream.readexactly(40)
        if header[0] >> 4 != 6:
            raise PairingTunnelError("The tunnel sent a non-IPv6 packet")
        length = struct.unpack(">H", header[4:6])[0]
        body = await self.stream.readexactly(length) if length else b""
        return header + body


async def open_tunnel(host, port, record, timeout=20):
    """Pair-verify, create listener, and establish TLS-PSK + CDTunnel."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    control = RemotePairingLink(reader, writer, record)
    await control.pair_verify()
    listener_port = await control.create_tcp_listener()

    reader2, writer2 = await asyncio.wait_for(
        asyncio.open_connection(host, listener_port), timeout
    )
    stream = await tls_psk.connect(reader2, writer2, control.psk)
    payload = json.dumps({"type": "clientHandshakeRequest", "mtu": 16000}).encode()
    request = CDTUNNEL + struct.pack(">H", len(payload)) + payload
    stream.write(request)
    await stream.drain()
    magic = await stream.readexactly(len(CDTUNNEL))
    if magic != CDTUNNEL:
        raise PairingTunnelError("The device did not answer the CDTunnel handshake")
    length = struct.unpack(">H", await stream.readexactly(2))[0]
    response = json.loads(await stream.readexactly(length))
    client = response.get("clientParameters") or {}
    address = client.get("address")
    server_address = response.get("serverAddress")
    if isinstance(address, str):
        address = address.split("/", 1)[0]
    if isinstance(server_address, str):
        server_address = server_address.split("/", 1)[0]
    rsd_port = response.get("serverRSDPort")
    if isinstance(rsd_port, str) and rsd_port.isdigit():
        rsd_port = int(rsd_port)
    if not address or not server_address or not isinstance(rsd_port, int):
        raise PairingTunnelError("Incomplete CDTunnel handshake: %r" % (response,))
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


async def _tcp_open(host, port, timeout=0.6):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return None
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return port


async def scan_ports(host=LOOPBACK_HOST, start=49152, count=64, timeout=0.5, batch=32):
    """Fast parallel port scan on LocalDevVPN loopback."""
    found = []
    ports = [start + offset for offset in range(count)]
    for chunk in range(0, len(ports), batch):
        results = await asyncio.gather(
            *[_tcp_open(host, port, timeout) for port in ports[chunk:chunk + batch]]
        )
        found.extend(p for p in results if p is not None)
        if found:
            break
    return sorted(found, key=lambda p: (p != start, p))


async def probe_loopback_port(host=LOOPBACK_HOST, explicit_port=0):
    """Return the open RPPairing port behind LocalDevVPN, or 0 if unreachable."""
    if explicit_port:
        return explicit_port if await _tcp_open(host, explicit_port, timeout=0.8) else 0
    if await _tcp_open(host, 49152, timeout=0.6):
        return 49152
    found = await scan_ports(host, start=49152, count=64, timeout=0.5, batch=32)
    return found[0] if found else 0


def check_vpn_sync(host=LOOPBACK_HOST):
    """Synchronous helper to check if LocalDevVPN is connected and responding."""
    try:
        return asyncio.run(probe_loopback_port(host))
    except Exception:
        return 0


class TunnelSession:
    """High-level RPPairing + RSD session over LocalDevVPN loopback."""

    def __init__(self, tunnel, stack, services, properties, xpc=None):
        self.tunnel = tunnel
        self.stack = stack
        self.services = services
        self.properties = properties
        self.xpc = xpc
        self.udid = storage.normalise_udid(properties.get("UniqueDeviceID", ""))
        self.product_type = properties.get("ProductType", "")
        self.product_version = properties.get("ProductVersion", "")
        self.address = tunnel["server_address"]

    async def close(self):
        try:
            await self.stack.close()
        except Exception:
            pass
        if self.xpc is not None:
            try:
                await self.xpc.close()
            except Exception:
                pass
        try:
            self.tunnel["stream"].close()
            await self.tunnel["stream"].wait_closed()
        except Exception:
            pass
        try:
            self.tunnel["control"].writer.close()
            await self.tunnel["control"].writer.wait_closed()
        except Exception:
            pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()


async def open_session(record=None, host=LOOPBACK_HOST, port=0):
    """Connect to the device over LocalDevVPN loopback and perform RSD discovery."""
    if record is None:
        record = load_record()
    if port:
        ports = [port]
    else:
        found_port = await probe_loopback_port(host)
        if not found_port:
            raise PairingTunnelError(
                "LocalDevVPN is not responding on %s. Open LocalDevVPN, enable the tunnel, and retry."
                % host
            )
        ports = [found_port]

    errors = []
    for candidate in ports:
        try:
            tunnel = await open_tunnel(host, candidate, record)
        except Exception as exc:
            errors.append("%s: %s" % (candidate, exc))
            continue
        stack = tcp6.TcpStack(tunnel["link"], tunnel["client_address"])
        await stack.start()
        try:
            connection = await stack.connect(tunnel["server_address"], tunnel["rsd_port"], timeout=15)
            services, properties, xpc = await remote_xpc.connect_rsd(connection, connection)
        except Exception as exc:
            await stack.close()
            errors.append("RSD on %s: %s" % (candidate, exc))
            continue
        session = TunnelSession(tunnel, stack, services, properties, xpc)
        if session.udid:
            storage.update_state(
                udid=session.udid,
                paired=True,
                peer_model=session.product_type or storage.load_state().get("peer_model", ""),
            )
        return session

    raise PairingTunnelError(
        "Could not open tunnel on %s: %s" % (host, "; ".join(errors[:3]))
    )


async def pair_with_device(
    timeout=300,
    pin=None,
    fresh_identity=False,
    on_pin=None,
    on_status=None,
    port=0,
):
    """Advertise BariStore over fast raw mDNS and complete Pair-Setup M1-M6.

    Pre-generates the 6-digit PIN and 3072-bit SRP server BEFORE advertising
    so the UI can display the PIN immediately and M1 -> M2 responds in <1ms.
    """
    if fresh_identity:
        identity = pairing.HostIdentity.generate()
        identity.save(storage.IDENTITY_PATH)
    else:
        identity = pairing.HostIdentity.load_or_create(storage.IDENTITY_PATH)

    # Pre-compute the SRP server (and 6-digit PIN) before opening the listener, so
    # the PIN can be shown immediately and M1 -> M2 answers in well under a
    # millisecond. Every extra connection iOS opens (it dials more than once)
    # gets its own SRP context but the SAME PIN, so whichever socket it finishes
    # on, the code the user sees is the right one.
    primed = pairing.prepare_srp_server(pin)
    chosen_pin = primed.pin
    primed_state = {"used": False}

    loop = asyncio.get_running_loop()
    result = loop.create_future()

    async def handle(reader, writer):
        if result.done():
            try:
                writer.close()
            except Exception:
                pass
            return
        peer = writer.get_extra_info("peername")
        peer_ip = (peer[0] if peer else "").split("%", 1)[0]

        if not primed_state["used"]:
            primed_state["used"] = True
            srp = primed
        else:
            srp = pairing.prepare_srp_server(chosen_pin)

        if on_status:
            on_status(
                "Device connected — enter PIN %s on the Settings screen" % chosen_pin
            )

        host = pairing.PairableHost(
            reader,
            writer,
            identity,
            name="BariStore",
            precomputed_srp=srp,
        )
        try:
            # pin_callback=None: the PIN never changes mid-session, so there is
            # nothing to re-display here.
            info = await host.accept(pin_callback=None)
            if not result.done():
                result.set_result((info, peer_ip))
        except Exception as exc:
            # A dropped socket, a probe, or a mistyped code must never take the
            # listener down: keep advertising the same PIN and wait for the next
            # connection.
            if on_status and not result.done():
                message = str(exc)
                if "code did not match" in message:
                    on_status(
                        "Wrong PIN entered. Tap BariStore in Settings again and enter %s."
                        % chosen_pin
                    )
                else:
                    on_status(
                        "Still waiting — tap BariStore in Settings and enter PIN %s."
                        % chosen_pin
                    )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "0.0.0.0", port)
    port = server.sockets[0].getsockname()[1]
    advertiser = mdns.Advertiser(identity, port, name="BariStore").start()

    # Publish the PIN only once the listener and the advertiser are live, so the
    # number on screen can always be typed in immediately.
    if on_pin:
        on_pin(chosen_pin)
    if on_status:
        on_status("Advertising BariStore — open Settings > Developer > Paired Macs")

    try:
        info, peer_ip = await asyncio.wait_for(result, timeout)
    except asyncio.TimeoutError:
        raise PairingTunnelError(
            "Pairing timed out. Make sure LocalDevVPN is connected and tap BariStore in Settings > Developer > Paired Macs."
        )
    finally:
        advertiser.stop()
        server.close()
        await server.wait_closed()

    record = pairing.PairingRecord(identity, info)
    record_path = storage.save_pairing_record(record)
    udid = storage.normalise_udid(info.get("udid", ""))
    return load_record(record_path), udid, info
