#!/usr/bin/env python3
"""Developer Mode & StikDebug-style JIT Enabler over the tunnel against mock services."""
import asyncio
import os
import plistlib
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from baristore import device


def _frame(value):
    payload = plistlib.dumps(value, fmt=plistlib.FMT_XML)
    return struct.pack(">I", len(payload)) + payload


async def _read_plist(reader):
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    return plistlib.loads(await reader.readexactly(length))


def _serve(script):
    async def handle(reader, writer):
        try:
            await _read_plist(reader)
            writer.write(_frame({"Request": "RSDCheckin"}))
            writer.write(_frame({"Request": "StartService"}))
            await writer.drain()
            for step in script:
                if step[0] == "recv":
                    await _read_plist(reader)
                elif step[0] == "send":
                    writer.write(_frame(step[1]))
                    await writer.drain()
                elif step[0] == "close":
                    return
        finally:
            try:
                writer.close()
            except Exception:
                pass

    return handle


class _Direct:
    class Conn:
        def __init__(self, reader, writer):
            self._reader = reader
            self._writer = writer

        async def readexactly(self, size):
            return await self._reader.readexactly(size)

        def write(self, data):
            self._writer.write(data)

        async def drain(self):
            await self._writer.drain()

        def close(self):
            try:
                self._writer.close()
            except Exception:
                pass

        async def wait_closed(self):
            try:
                await self._writer.wait_closed()
            except Exception:
                pass

    async def connect(self, host, port, timeout=10):
        reader, writer = await asyncio.open_connection(host, port)
        return _Direct.Conn(reader, writer)


class _Sess:
    def __init__(self, services):
        self.stack = _Direct()
        self.address = "127.0.0.1"
        self.services = services
        self.udid = "a" * 40


async def _status(reply, services=None):
    server = await asyncio.start_server(
        _serve([("recv", None), ("send", reply)]), "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    try:
        services = services or {"com.apple.mobile.lockdown.remote.trusted": {"Port": port}}
        return await device.devmode_status(_Sess(services))
    finally:
        server.close()
        await server.wait_closed()


async def test_jit_enabler():
    """Verify StikDebug-style GDB Remote Serial Protocol JIT enable over debugproxy."""
    gdb_received = []

    async def debugproxy_handler(reader, writer):
        # Receive initial "++"
        plus = await reader.readexactly(2)
        assert plus == b"++"
        # Receive QStartNoAckMode
        pkt1 = await device._gdb_read_packet(reader, noack=True)
        gdb_received.append(pkt1)
        writer.write(b"+")
        writer.write(device._gdb_packet("OK"))
        await writer.drain()
        # Receive vAttachName;<hex>
        pkt2 = await device._gdb_read_packet(reader, noack=True)
        gdb_received.append(pkt2)
        writer.write(device._gdb_packet("T11thread:1;"))
        await writer.drain()
        # Receive D (detach)
        pkt3 = await device._gdb_read_packet(reader, noack=True)
        gdb_received.append(pkt3)
        writer.write(device._gdb_packet("OK"))
        await writer.drain()
        writer.close()

    install_server = await asyncio.start_server(
        _serve(
            [
                ("recv", None),
                (
                    "send",
                    {
                        "LookupResult": {
                            "com.dolphin.ios.TEAM": {
                                "CFBundleExecutable": "DolphiniOS",
                                "Path": "/private/var/containers/Bundle/Application/UUID/DolphiniOS.app",
                            }
                        }
                    },
                ),
            ]
        ),
        "127.0.0.1",
        0,
    )
    debug_server = await asyncio.start_server(debugproxy_handler, "127.0.0.1", 0)
    try:
        services = {
            device.INSTALL_SERVICE: {"Port": install_server.sockets[0].getsockname()[1]},
            device.DEBUG_PROXY_SERVICE: {"Port": debug_server.sockets[0].getsockname()[1]},
        }
        res = await device.enable_jit(_Sess(services), "com.dolphin.ios.TEAM")
        assert res["executable"] == "DolphiniOS"
        assert gdb_received == [
            "QStartNoAckMode",
            "vAttachName;" + "DolphiniOS".encode().hex().upper(),
            "D",
        ]
        print("ok  stikdebug-style JIT enabler over debugproxy")
    finally:
        install_server.close()
        debug_server.close()
        await install_server.wait_closed()
        await debug_server.wait_closed()


async def main():
    assert await _status({"Value": True}) is True
    print("ok  status on")
    assert await _status({"Value": False}) is False
    print("ok  status off")
    assert await _status({"Error": "MissingValue"}) is None
    print("ok  status unreadable")

    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"success": True})]), "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    try:
        await device.devmode_show_switch(
            _Sess({"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
        )
        print("ok  show switch")
    finally:
        server.close()
        await server.wait_closed()

    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"Error": "Device has a passcode set"})]),
        "127.0.0.1",
        0,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        try:
            await device.devmode_turn_on(
                _Sess({"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
            )
        except device.DeviceServiceError as exc:
            assert str(exc) == "passcode-set", exc
            print("ok  turn on passcode marker")
        else:
            raise AssertionError("passcode refusal did not raise")
    finally:
        server.close()
        await server.wait_closed()

    await test_jit_enabler()


if __name__ == "__main__":
    asyncio.run(main())
