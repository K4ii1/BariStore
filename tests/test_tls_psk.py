#!/usr/bin/env python3
"""Interop test: pure-Python TLS 1.2 PSK client vs OpenSSL (Python's ssl)."""
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import asyncio

import tls_psk

PSK = bytes.fromhex("00112233445566778899aabbccddeeff"
                    "00112233445566778899aabbccddeeff")


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_server(cipher):
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "tls_psk_echo_server.py"),
         str(port), PSK.hex(), cipher],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            sock.close()
            return process, port
        except OSError:
            time.sleep(0.05)
    process.terminate()
    raise RuntimeError("test TLS server did not start")


async def _roundtrip(port, psk):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    stream = await tls_psk.connect(reader, writer, psk)
    payload = bytes(range(256)) * 1024
    stream.write(payload)
    await stream.drain()
    received = await asyncio.wait_for(stream.readexactly(len(payload)), 10)
    stream.close()
    return received == payload


def test_aes256_sha384():
    process, port = start_server("PSK-AES256-CBC-SHA384")
    try:
        assert asyncio.run(_roundtrip(port, PSK))
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_aes128_sha():
    process, port = start_server("PSK-AES128-CBC-SHA")
    try:
        assert asyncio.run(_roundtrip(port, PSK))
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_wrong_psk_fails():
    process, port = start_server("PSK-AES256-CBC-SHA384")

    async def attempt():
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await tls_psk.connect(reader, writer, b"\x00" * 32)
        except Exception:
            return True
        return False

    try:
        assert asyncio.run(attempt())
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    test_aes256_sha384()
    print("ok  AES256-CBC-SHA384")
    test_aes128_sha()
    print("ok  AES128-CBC-SHA")
    test_wrong_psk_fails()
    print("ok  wrong PSK rejected")
