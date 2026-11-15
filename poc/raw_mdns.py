#!/usr/bin/env python3
# =============================================================================
#  BariSign — raw mDNS advertiser for the pairing host (MIT, experimental)
#
#  a-Shell cannot use the DNS-SD API (its signed Info.plist has no
#  NSBonjourServices entry, so registration fails with -65555).  This module
#  publishes the same `_remotepairing-pairable-host._tcp` records directly over
#  mDNS multicast, without the Bonjour API.  It is a fallback: if iOS blocks
#  multicast without the multicast entitlement, `start()` raises and the caller
#  must use another pairing host.
#
#  Records: PTR (service -> instance), SRV (instance -> host, port), TXT
#  (name/identifier/authTag/model/flags/ver/minVer) and A (host -> signer IP).
#  Announcements are repeated every second; if port 5353 can be shared, incoming
#  PTR queries are answered too.
#
#  UNTESTED ON A DEVICE.  Packet construction is unit-tested on Linux.
# =============================================================================

import asyncio
import socket
import struct

from ashell_bonjour import _txt_record
from pairing import mdns_txt

MCAST = "224.0.0.251"
SERVICE = "_remotepairing-pairable-host._tcp.local"
HOST = "barisign-signer.local"
INSTANCE = "BariSign." + SERVICE


def _name(text):
    out = b""
    for label in text.rstrip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _rr(name, rtype, rclass, ttl, rdata):
    return _name(name) + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def build_announcement(identity, port, ipv4, ttl=120):
    txt = _txt_record(mdns_txt(identity))
    # PTR is shared; SRV/TXT/A are unique and carry the cache-flush bit.
    ptr = _rr(SERVICE, 12, 1, ttl, _name(INSTANCE))
    srv = _rr(INSTANCE, 33, 0x8001, ttl,
              struct.pack(">HHH", 0, 0, int(port)) + _name(HOST))
    txt_rr = _rr(INSTANCE, 16, 0x8001, ttl, txt)
    address = _rr(HOST, 1, 0x8001, ttl, socket.inet_aton(ipv4))
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 4, 0, 0)
    return header + ptr + srv + txt_rr + address


def wifi_ipv4():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return ""
    finally:
        probe.close()


class Advertiser:
    def __init__(self, identity, port, target_ip=""):
        self.identity = identity
        self.port = int(port)
        self.target_ip = target_ip
        self.ipv4 = wifi_ipv4()
        self.sock = None
        self.bound = False
        self.packet = b""
        self._task = None
        self.error = ""

    def start(self):
        if not self.ipv4:
            raise RuntimeError("raw mDNS: no Wi-Fi IPv4 address")
        self.packet = build_announcement(self.identity, self.port, self.ipv4)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            sock.bind(("", 5353))
            self.bound = True
        except OSError:
            self.bound = False
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(self.ipv4))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except OSError as exc:
            sock.close()
            raise RuntimeError("raw mDNS: cannot select the Wi-Fi interface: %s" % exc)
        if self.bound:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                socket.inet_aton(MCAST) + socket.inet_aton(self.ipv4))
            except OSError:
                pass
        try:
            sock.sendto(self.packet, (MCAST, 5353))
            if self.target_ip:
                sock.sendto(self.packet, (self.target_ip, 5353))
        except OSError as exc:
            sock.close()
            raise RuntimeError("raw mDNS: multicast send failed: %s" % exc)
        sock.setblocking(False)
        self.sock = sock
        self._task = asyncio.create_task(self._loop())
        return self

    async def _loop(self):
        while True:
            await asyncio.sleep(1)
            try:
                self.sock.sendto(self.packet, (MCAST, 5353))
                if self.target_ip:
                    self.sock.sendto(self.packet, (self.target_ip, 5353))
            except OSError:
                pass
            if not self.bound:
                continue
            while True:
                try:
                    data, address = self.sock.recvfrom(9000)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                if b"_remotepairing" not in data and b"BariSign" not in data:
                    continue
                try:
                    self.sock.sendto(self.packet, (MCAST, 5353))
                    self.sock.sendto(self.packet, (address[0], 5353))
                except OSError:
                    pass

    def stop(self):
        if self._task is not None:
            self._task.cancel()
            self._task = None
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
