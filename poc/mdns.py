#!/usr/bin/env python3
# =============================================================================
#  BariSign — Bonjour/mDNS helpers (MIT)
#
#  On the signer (a-Shell/iOS) raw multicast sockets are not available, so
#  registration and browsing go through the system DNS-SD API (libsystem_dnssd,
#  reached with ctypes) exactly as the existing pair_probe.py does.  On Linux
#  (development only) a small raw mDNS browser is used so the parser can be
#  exercised without a device.
#
#  UNTESTED ON A DEVICE (browse path); registration reuses the device-verified
#  approach from ashell_bonjour.py.
# =============================================================================

import ctypes
import select
import socket
import struct
import sys
import time

from ashell_bonjour import BonjourResponder, _load_dnssd, is_ashell

PAIRABLE_HOST = "_remotepairing-pairable-host._tcp"
REMOTE_PAIRING = "_remotepairing._tcp"


# --------------------------------------------------------------------------
# DNS packet parsing (used by the Linux browser and the unit tests)
# --------------------------------------------------------------------------

def decode_name(data, offset):
    labels = []
    jumped = False
    end = offset
    guard = 0
    while True:
        guard += 1
        if guard > 128 or offset >= len(data):
            raise ValueError("bad DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            return ".".join(labels), end
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("bad DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            continue
        if offset + 1 + length > len(data):
            raise ValueError("bad DNS label")
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset


def parse_packet(data):
    if len(data) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(data, offset)
        offset += 4
    records = []
    for _ in range(an + ns + ar):
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        record = {"name": name, "type": rtype, "ttl": ttl}
        if rtype == 12:                                  # PTR
            record["target"], _ = decode_name(data, offset - rdlength)
        elif rtype == 33 and len(rdata) >= 6:            # SRV
            priority, weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = decode_name(data, offset - rdlength + 6)
            record.update({"port": port, "target": target, "priority": priority,
                           "weight": weight})
        elif rtype == 16:                                # TXT
            record["txt"] = parse_txt(rdata)
        elif rtype == 1 and len(rdata) == 4:
            record["address"] = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and len(rdata) == 16:
            record["address"] = socket.inet_ntop(socket.AF_INET6, rdata)
        records.append(record)
    return records


def parse_txt(raw):
    result = {}
    pos = 0
    while pos < len(raw):
        length = raw[pos]
        pos += 1
        entry = raw[pos:pos + length].decode("utf-8", "replace")
        pos += length
        if "=" in entry:
            key, value = entry.split("=", 1)
            result[key] = value
        elif entry:
            result[entry] = ""
    return result


def _encode_query(name, qtype=12):
    labels = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode()
        labels += bytes([len(raw)]) + raw
    labels += b"\x00"
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + labels + struct.pack(">HH", qtype, 1)


def browse_raw(service_type, timeout=4.0):
    """Best-effort raw multicast browse for Linux development."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", 5353))
        group = socket.inet_aton("224.0.0.251")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        group + socket.inet_aton("0.0.0.0"))
    except OSError:
        pass
    sock.setblocking(False)
    query = _encode_query(service_type)
    try:
        sock.sendto(query, ("224.0.0.251", 5353))
    except OSError:
        pass
    records = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0.05, deadline - time.monotonic()))
        if not ready:
            continue
        try:
            data, _ = sock.recvfrom(9000)
        except OSError:
            continue
        try:
            records.extend(parse_packet(data))
        except ValueError:
            continue
    sock.close()
    return _assemble(records, service_type)


def _assemble(records, service_type):
    instances = {}
    for record in records:
        if record["type"] == 12 and record["name"].rstrip(".").lower() == service_type.rstrip(".").lower():
            instances.setdefault(record["target"], {"instance": record["target"]})
    # fall back to any PTR that mentions the type (compressed names vary)
    for record in records:
        if record["type"] == 33:
            entry = instances.setdefault(record["name"], {"instance": record["name"]})
            entry["host"] = record["target"]
            entry["port"] = record["port"]
        elif record["type"] == 16:
            entry = instances.setdefault(record["name"], {"instance": record["name"]})
            entry["properties"] = record.get("txt", {})
        elif record["type"] in (1, 28):
            for entry in instances.values():
                if entry.get("host") == record["name"]:
                    entry.setdefault("addresses", []).append(record["address"])
    return [entry for entry in instances.values() if "port" in entry]


# --------------------------------------------------------------------------
# Apple DNS-SD browse/resolve
# --------------------------------------------------------------------------

_BROWSE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                              ctypes.c_int32, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_char_p, ctypes.c_void_p)
_RESOLVE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_int32, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_uint16, ctypes.c_uint16, ctypes.c_void_p,
                               ctypes.c_void_p)


class _AppleBrowser:
    def __init__(self, service_type):
        self.service_type = service_type
        self.library = _load_dnssd()
        self.browse_ref = ctypes.c_void_p()
        self.resolve_refs = []
        self.results = {}
        self.callbacks = []

    def start(self):
        lib = self.library
        lib.DNSServiceBrowse.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32,
                                         ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p,
                                         _BROWSE_CB, ctypes.c_void_p]
        lib.DNSServiceBrowse.restype = ctypes.c_int32
        lib.DNSServiceResolve.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32,
                                          ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p,
                                          ctypes.c_char_p, _RESOLVE_CB, ctypes.c_void_p]
        lib.DNSServiceResolve.restype = ctypes.c_int32
        lib.DNSServiceRefSockFD.argtypes = [ctypes.c_void_p]
        lib.DNSServiceRefSockFD.restype = ctypes.c_int
        lib.DNSServiceProcessResult.argtypes = [ctypes.c_void_p]
        lib.DNSServiceProcessResult.restype = ctypes.c_int32
        lib.DNSServiceRefDeallocate.argtypes = [ctypes.c_void_p]
        self._browse_cb = _BROWSE_CB(self._on_browse)
        self.callbacks.append(self._browse_cb)
        error = lib.DNSServiceBrowse(ctypes.byref(self.browse_ref), 0, 0,
                                     self.service_type.encode(), None,
                                     self._browse_cb, None)
        if error:
            raise RuntimeError("DNSServiceBrowse failed: %d" % error)

    def _on_browse(self, _ref, _flags, iface, error, name, regtype, domain, _context):
        if error or not name or not regtype:
            return
        ref = ctypes.c_void_p()
        callback = _RESOLVE_CB(lambda *args: self._on_resolve(*args))
        self.callbacks.append(callback)
        result = self.library.DNSServiceResolve(
            ctypes.byref(ref), 0, iface, name, regtype, domain or b"local.", callback, None)
        if result == 0 and ref:
            self.resolve_refs.append(ref)

    def _on_resolve(self, _ref, _flags, _iface, error, _fullname, hosttarget, port,
                    txt_len, txt_record, _context):
        if error or not hosttarget or not port:
            return
        port = socket.ntohs(port)
        txt = {}
        if txt_record and txt_len:
            raw = ctypes.string_at(txt_record, txt_len)
            txt = parse_txt(raw)
        host = hosttarget.decode("utf-8", "replace").rstrip(".")
        entry = self.results.setdefault(host, {
            "instance": _fullname.decode("utf-8", "replace") if _fullname else host,
            "host": host, "port": port, "properties": txt, "addresses": [],
        })
        entry["properties"] = txt
        try:
            for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
                    host, port, 0, socket.SOCK_STREAM):
                address = sockaddr[0]
                if address not in entry["addresses"]:
                    entry["addresses"].append(address)
        except OSError:
            pass

    def run(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            refs = [self.browse_ref] + self.resolve_refs
            fds = []
            for ref in refs:
                if ref:
                    fd = self.library.DNSServiceRefSockFD(ref)
                    if fd >= 0:
                        fds.append((fd, ref))
            if not fds:
                break
            ready, _, _ = select.select([fd for fd, _ in fds], [], [],
                                        max(0.05, deadline - time.monotonic()))
            for fd, ref in fds:
                if fd in ready:
                    self.library.DNSServiceProcessResult(ref)
        return list(self.results.values())

    def close(self):
        for ref in self.resolve_refs:
            try:
                self.library.DNSServiceRefDeallocate(ref)
            except Exception:                               # noqa: BLE001
                pass
        if self.browse_ref:
            try:
                self.library.DNSServiceRefDeallocate(self.browse_ref)
            except Exception:                               # noqa: BLE001
                pass


def browse(service_type, timeout=4.0):
    if is_ashell() or sys.platform == "darwin":
        browser = _AppleBrowser(service_type)
        browser.start()
        try:
            return browser.run(timeout)
        finally:
            browser.close()
    return browse_raw(service_type, timeout)


def register(service_type, name, port, txt):
    """Return an async context manager that advertises the service."""
    if is_ashell() or sys.platform == "darwin":
        return BonjourResponder(service_type, name, port, txt)
    return _NullResponder()


class _NullResponder:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None
