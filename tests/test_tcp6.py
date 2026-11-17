#!/usr/bin/env python3
"""Linux-only TUN link used by the TCP-stack test."""
import asyncio
import fcntl
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from baristore import tcp6

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
DEVICE = "baritun"
KERNEL_IP = "fd00::1"
STACK_IP = "fd00::2"


def _sudo(*args, check=True):
    result = subprocess.run(
        ["sudo", "-n"] + list(args),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check and result.returncode:
        raise RuntimeError("sudo ip %s failed" % " ".join(args))


def setup():
    _sudo("ip", "link", "del", DEVICE, check=False)
    _sudo(
        "ip",
        "tuntap",
        "add",
        "dev",
        DEVICE,
        "mode",
        "tun",
        "user",
        os.environ.get("USER", "codespace"),
    )
    fd = open_tun()
    _sudo("ip", "-6", "addr", "add", KERNEL_IP + "/128", "dev", DEVICE)
    _sudo("ip", "link", "set", DEVICE, "up")
    _sudo("ip", "-6", "route", "add", STACK_IP + "/128", "dev", DEVICE, check=False)
    return fd


def teardown():
    _sudo("ip", "link", "del", DEVICE, check=False)


def open_tun():
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", DEVICE.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    os.set_blocking(fd, False)
    return fd


class TunLink:
    def __init__(self, fd, loop):
        self.fd = fd
        self.loop = loop
        self.queue = asyncio.Queue()

    def _readable(self):
        while True:
            try:
                packet = os.read(self.fd, 65536)
            except (BlockingIOError, OSError):
                return
            if not packet:
                return
            self.queue.put_nowait(packet)

    def send(self, packet):
        os.write(self.fd, packet)

    async def recv(self):
        if self.queue.empty():
            self.loop.add_reader(self.fd, self._readable)
            try:
                return await self.queue.get()
            finally:
                self.loop.remove_reader(self.fd)
        return await self.queue.get()


async def _check():
    loop = asyncio.get_running_loop()
    fd = SETUP_FD
    link = TunLink(fd, loop)

    async def echo(reader, writer):
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, KERNEL_IP, 9000)
    stack = tcp6.TcpStack(link, STACK_IP)
    await stack.start()
    conn = await stack.connect(KERNEL_IP, 9000, timeout=10)
    print("handshake ok")
    payload = bytes(range(256)) * 4096
    conn.write(payload)
    await asyncio.wait_for(conn.drain(), 30)
    got = await asyncio.wait_for(conn.readexactly(len(payload)), 30)
    assert got == payload, "echo mismatch"
    print("echo ok: %d bytes" % len(got))
    conn.close()

    second = await stack.connect(KERNEL_IP, 9000, timeout=10)
    second.write(b"second connection")
    await asyncio.wait_for(second.drain(), 10)
    assert await asyncio.wait_for(second.readexactly(17), 10) == b"second connection"
    second.close()
    print("two connections ok")
    await stack.close()
    server.close()
    await server.wait_closed()
    os.close(fd)


SETUP_FD = None

if __name__ == "__main__":
    SETUP_FD = setup()
    try:
        asyncio.run(_check())
    finally:
        teardown()
