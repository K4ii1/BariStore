#!/usr/bin/env python3
# =============================================================================
#  BariStore — Minimal Userspace IPv6/TCP Client (MIT)
#
#  The RPPairing tunnel is an L3 link carrying raw IPv6 packets. This module
#  provides outbound TCP connections over that link for RSD, installation_proxy,
#  AFC, house_arrest, lockdownd, AMFI, and debug_proxy.
# =============================================================================

import asyncio
import ipaddress
import os
import struct

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PUSH = 0x08
TCP_ACK = 0x10

MASK = 0xFFFFFFFF
MAX_WINDOW = 65535
DEFAULT_MSS = 1340
SYN_MSS = 1340


def seq_lt(a, b):
    return ((a - b) & MASK) > 0x7FFFFFFF


def seq_le(a, b):
    return a == b or seq_lt(a, b)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class TcpError(Exception):
    pass


class TcpConnection:
    """A single outbound TCP connection carried over an L3 IPv6 link."""

    def __init__(self, stack, host, port):
        self.stack = stack
        self.host = host
        self.host_packed = ipaddress.IPv6Address(host).packed
        self.port = port
        self.local_port = 0
        self.iss = 0
        self.snd_una = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_wnd = MAX_WINDOW
        self.mss = DEFAULT_MSS
        self.peer_window_scale = 0
        self.state = "CLOSED"
        self._out = bytearray()
        self._inbuf = bytearray()
        self._ooo = {}
        self._eof = False
        self._error = None
        self._syn_sent = 0.0
        self._retx_at = 0.0
        self._rto = 0.4
        self._syn_event = asyncio.Event()
        self._data_event = asyncio.Event()
        self._drain_event = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._fin_sent = False
        self._closed = False

    def feed(self, flags, seq, ack, window, payload):
        now = asyncio.get_running_loop().time()
        if flags & TCP_RST:
            self._fail(TcpError("the device reset the connection"))
            return
        if self.state == "SYN_SENT":
            if (flags & TCP_SYN) and (flags & TCP_ACK):
                self.snd_una = ack & MASK
                self.snd_nxt = (self.iss + 1) & MASK
                self.rcv_nxt = (seq + 1) & MASK
                self.snd_wnd = window
                self.state = "ESTABLISHED"
                self._retx_at = now + self._rto
                self._syn_event.set()
                self._send_ack()
            return
        if self.state not in ("ESTABLISHED", "FIN_WAIT"):
            return

        if flags & TCP_ACK:
            if seq_le(self.snd_una, ack & MASK) and seq_le(ack & MASK, self.snd_nxt):
                acked = (ack - self.snd_una) & MASK
                if acked and acked <= len(self._out):
                    del self._out[:acked]
                    self.snd_una = ack & MASK
                    self._rto = 0.4
                    self._retx_at = now + self._rto
                    self._drain_event.set()
                    if self._fin_sent and self.snd_una == self.snd_nxt:
                        self._closed_event.set()
            self.snd_wnd = min(MAX_WINDOW * 16, window << self.peer_window_scale)

        if payload or (flags & TCP_PUSH):
            self._accept_data(seq, payload)
        if flags & TCP_FIN:
            if self._accept_fin(seq, payload):
                self._send_ack()
        if flags & TCP_SYN:
            self._send_ack()

    def _accept_data(self, seq, payload):
        if not payload:
            return
        if seq == self.rcv_nxt:
            self._inbuf += payload
            self.rcv_nxt = (self.rcv_nxt + len(payload)) & MASK
            self._drain_ooo()
            self._data_event.set()
            self._send_ack()
        elif seq_lt(self.rcv_nxt, seq):
            if seq_lt(seq, (self.rcv_nxt + 0x100000) & MASK):
                self._ooo[seq] = payload
            self._send_ack()
        else:
            self._send_ack()

    def _drain_ooo(self):
        while True:
            hit = None
            for seq in self._ooo:
                if seq == self.rcv_nxt:
                    hit = seq
                    break
                if seq_lt(seq, self.rcv_nxt):
                    del self._ooo[seq]
                    break
            if hit is None:
                return
            payload = self._ooo.pop(hit)
            self._inbuf += payload
            self.rcv_nxt = (self.rcv_nxt + len(payload)) & MASK

    def _accept_fin(self, seq, payload):
        fin_seq = (seq + len(payload)) & MASK
        if fin_seq == self.rcv_nxt:
            self.rcv_nxt = (self.rcv_nxt + 1) & MASK
            self._eof = True
            self._data_event.set()
            if not self._out:
                self._closed_event.set()
            return True
        return False

    def _send_ack(self):
        if self.state in ("ESTABLISHED", "FIN_WAIT"):
            self.stack.send_segment(self, TCP_ACK, self.snd_nxt, self.rcv_nxt, b"")

    async def handshake(self, timeout):
        loop = asyncio.get_running_loop()
        self.local_port = self.stack.allocate_port()
        self.iss = int.from_bytes(os.urandom(4), "big") & MASK
        self.snd_una = self.iss
        self.snd_nxt = (self.iss + 1) & MASK
        self.state = "SYN_SENT"
        self._syn_sent = loop.time()
        self.stack.register(self)
        self.stack.send_segment(
            self,
            TCP_SYN,
            self.iss,
            0,
            b"",
            options=struct.pack(">BBH", 2, 4, SYN_MSS),
        )
        try:
            await asyncio.wait_for(self._syn_event.wait(), timeout)
        except asyncio.TimeoutError:
            self._fail(TcpError("no TCP SYN-ACK from the device"))
            raise
        if self._error:
            raise self._error
        self._send_ack()

    def _fail(self, exc):
        if self._error is None:
            self._error = exc
        self.state = "CLOSED"
        self._syn_event.set()
        self._data_event.set()
        self._drain_event.set()
        self._closed_event.set()

    def write(self, data):
        if self._error:
            raise self._error
        if self.state != "ESTABLISHED":
            raise TcpError("connection is not established")
        self._out += data

    async def drain(self):
        loop = asyncio.get_running_loop()
        while True:
            if self._error:
                raise self._error
            inflight = (self.snd_nxt - self.snd_una) & MASK
            if inflight > len(self._out):
                inflight = 0
            if len(self._out) > inflight and self.snd_wnd > inflight:
                self._send_pending()
                continue
            if not self._out:
                return
            self._drain_event.clear()
            try:
                await asyncio.wait_for(self._drain_event.wait(), 0.5)
            except asyncio.TimeoutError:
                pass
            if loop.time() >= self._retx_at:
                self._retransmit()

    def _send_pending(self):
        if self.state != "ESTABLISHED" or self._error:
            return
        sent = (self.snd_nxt - self.snd_una) & MASK
        if sent > len(self._out):
            sent = 0
        while sent < len(self._out):
            inflight = (self.snd_nxt - self.snd_una) & MASK
            room = min(self.snd_wnd - inflight, MAX_WINDOW)
            if room <= 0:
                break
            chunk = bytes(self._out[sent:sent + min(self.mss, room)])
            self.stack.send_segment(self, TCP_ACK | TCP_PUSH, self.snd_nxt, self.rcv_nxt, chunk)
            self.snd_nxt = (self.snd_nxt + len(chunk)) & MASK
            sent += len(chunk)
        self._retx_at = asyncio.get_running_loop().time() + self._rto

    def _retransmit(self):
        now = asyncio.get_running_loop().time()
        inflight = (self.snd_nxt - self.snd_una) & MASK
        if inflight and inflight <= len(self._out):
            chunk = bytes(self._out[:min(self.mss, inflight)])
            self.stack.send_segment(self, TCP_ACK | TCP_PUSH, self.snd_una, self.rcv_nxt, chunk)
        self._rto = min(self._rto * 2, 4.0)
        self._retx_at = now + self._rto

    def pending(self):
        inflight = (self.snd_nxt - self.snd_una) & MASK
        if inflight > len(self._out):
            inflight = 0
        return len(self._out) - inflight

    async def readexactly(self, size):
        while len(self._inbuf) < size:
            if self._error:
                raise self._error
            if self._eof:
                data = bytes(self._inbuf)
                self._inbuf.clear()
                raise asyncio.IncompleteReadError(data, size)
            self._data_event.clear()
            await self._data_event.wait()
        data = bytes(self._inbuf[:size])
        del self._inbuf[:size]
        return data

    async def read(self, size=-1):
        while not self._inbuf:
            if self._error:
                raise self._error
            if self._eof:
                return b""
            self._data_event.clear()
            await self._data_event.wait()
        if size is None or size < 0 or size >= len(self._inbuf):
            data = bytes(self._inbuf)
            self._inbuf.clear()
            return data
        data = bytes(self._inbuf[:size])
        del self._inbuf[:size]
        return data

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.state == "ESTABLISHED" and not self._fin_sent:
            self._fin_sent = True
            self.stack.send_segment(self, TCP_FIN | TCP_ACK, self.snd_nxt, self.rcv_nxt, b"")
            self.snd_nxt = (self.snd_nxt + 1) & MASK
            self.state = "FIN_WAIT"
        self.stack.unregister(self)

    async def wait_closed(self):
        try:
            await asyncio.wait_for(self._closed_event.wait(), 1.0)
        except asyncio.TimeoutError:
            pass


class TcpStack:
    def __init__(self, link, local_ip):
        self.link = link
        self.local_ip = local_ip
        self.local_packed = ipaddress.IPv6Address(local_ip).packed
        self.connections = {}
        self._ports = set()
        self._reader_task = None
        self._timer_task = None
        self._closed = False

    async def start(self):
        self._reader_task = asyncio.create_task(self._read_loop())
        self._timer_task = asyncio.create_task(self._timer_loop())

    async def close(self):
        self._closed = True
        for task in (self._reader_task, self._timer_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass
        for conn in list(self.connections.values()):
            conn._fail(TcpError("stack closed"))
        self.connections.clear()

    def allocate_port(self):
        for _ in range(200):
            port = 20000 + int.from_bytes(os.urandom(2), "big") % 40000
            if port not in self._ports:
                self._ports.add(port)
                return port
        raise TcpError("could not allocate a local TCP port")

    def register(self, conn):
        self.connections[(conn.host_packed, conn.local_port, conn.port)] = conn

    def unregister(self, conn):
        self.connections.pop((conn.host_packed, conn.local_port, conn.port), None)

    async def connect(self, host, port, timeout=15):
        conn = TcpConnection(self, host, port)
        await conn.handshake(timeout)
        return conn

    def build_segment(self, conn, flags, seq, ack, payload, options=b""):
        src = self.local_packed
        dst = conn.host_packed
        data_offset = 5 + (len(options) // 4)
        offset_flags = (data_offset << 12) | flags
        header = struct.pack(
            ">HHIIHHHH",
            conn.local_port,
            conn.port,
            seq & MASK,
            ack & MASK,
            offset_flags,
            MAX_WINDOW,
            0,
            0,
        )
        tcp = header + options + payload
        pseudo = src + dst + struct.pack(">I", len(tcp)) + b"\x00\x00\x00\x06"
        csum = checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack(">H", csum) + tcp[18:]
        ip = struct.pack(">IHBB", 6 << 28, len(tcp), 6, 64) + src + dst
        return ip + tcp

    def send_segment(self, conn, flags, seq, ack, payload, options=b""):
        packet = self.build_segment(conn, flags, seq, ack, payload, options)
        try:
            self.link.send(packet)
        except Exception:
            pass

    async def _read_loop(self):
        while not self._closed:
            try:
                packet = await self.link.recv()
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(0.05)
                continue
            try:
                self._handle_packet(packet)
            except Exception:
                continue

    def _handle_packet(self, packet):
        if len(packet) < 40 or (packet[0] >> 4) != 6:
            return
        if packet[6] == 58:
            self._handle_icmpv6(packet)
            return
        if packet[24:40] != self.local_packed:
            return
        next_header = packet[6]
        offset = 40
        while next_header in (0, 43, 44, 60):
            if next_header == 44:
                if len(packet) < offset + 8:
                    return
                next_header = packet[offset]
                offset += (packet[offset + 1] + 1) * 8
            else:
                if len(packet) < offset + 2:
                    return
                next_header = packet[offset]
                offset += (packet[offset + 1] + 1) * 8
        if next_header != 6:
            return
        tcp = packet[offset:]
        if len(tcp) < 20:
            return
        sport, dport, seq, ack, off_flags, window = struct.unpack(">HHIIHH", tcp[:16])
        data_offset = (off_flags >> 12) * 4
        if data_offset < 20 or len(tcp) < data_offset:
            return
        flags = off_flags & 0x3F
        payload = tcp[data_offset:]
        conn = self.connections.get((packet[8:24], dport, sport))
        if conn is None:
            return
        if (flags & TCP_SYN) and (flags & TCP_ACK):
            mss = _parse_option(tcp[20:data_offset], 2)
            if mss and len(mss) == 2:
                conn.mss = max(536, min(struct.unpack(">H", mss)[0], 1400))
            scale = _parse_option(tcp[20:data_offset], 3)
            if scale and len(scale) == 1:
                conn.peer_window_scale = min(scale[0], 14)
        conn.feed(flags, seq, ack, window, payload)

    def _handle_icmpv6(self, packet):
        if len(packet) < 48:
            return
        payload_len = struct.unpack(">H", packet[4:6])[0]
        body = packet[40:40 + payload_len]
        if len(body) < 24 or body[0] != 135:
            return
        target = body[8:24]
        if target != self.local_packed:
            return
        src = packet[8:24]
        dst = packet[24:40]
        if dst != self.local_packed and not (len(dst) > 1 and dst[0] == 0xFF and dst[1] == 0x02):
            return
        flags = struct.pack(">I", 0x60000000)
        option = b"\x02\x01\x02\x00\x00\x00\x00\x02"
        icmp = b"\x88\x00\x00\x00" + flags + self.local_packed + option
        pseudo = self.local_packed + src + struct.pack(">I", len(icmp)) + b"\x00\x00\x00\x3a"
        csum = checksum(pseudo + icmp)
        icmp = icmp[:2] + struct.pack(">H", csum) + icmp[4:]
        ip = struct.pack(">IHBB", 6 << 28, len(icmp), 58, 255) + self.local_packed + src
        try:
            self.link.send(ip + icmp)
        except Exception:
            pass

    async def _timer_loop(self):
        while not self._closed:
            await asyncio.sleep(0.1)
            now = asyncio.get_running_loop().time()
            for conn in list(self.connections.values()):
                if conn.state == "SYN_SENT" and now - conn._syn_sent > 5:
                    conn._fail(TcpError("TCP handshake timed out"))
                elif conn.state == "ESTABLISHED":
                    inflight = (conn.snd_nxt - conn.snd_una) & MASK
                    if inflight and now >= conn._retx_at:
                        conn._retransmit()
                    elif not inflight and conn.pending():
                        conn._send_pending()


def _parse_option(options, kind):
    pos = 0
    while pos + 1 < len(options):
        option = options[pos]
        if option == 0:
            return None
        if option == 1:
            pos += 1
            continue
        length = options[pos + 1]
        if length < 2 or pos + length > len(options):
            return None
        if option == kind:
            return options[pos + 2:pos + length]
        pos += length
    return None
