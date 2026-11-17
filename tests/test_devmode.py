#!/usr/bin/env python3
"""Developer Mode over the tunnel, against fake services (no device)."""
import asyncio
import os
import struct
import sys
import plistlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import devmode


def _frame(value):
    payload = plistlib.dumps(value, fmt=plistlib.FMT_XML)
    return struct.pack(">I", len(payload)) + payload


async def _read_plist(reader):
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    return plistlib.loads(await reader.readexactly(length))


def _serve(script):
    """A fake service: plays the RSDCheckin opening, then answers from script.

    script: list of ("recv"|"send"|"close", value?). "close" drops the conn.
    """
    async def handle(reader, writer):
        try:
            await _read_plist(reader)              # RSDCheckin
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
            except Exception:                                   # noqa: BLE001
                pass
    return handle


async def _one(script):
    server = await asyncio.start_server(_serve(script), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        import device_services
        from tcp6 import TcpStack  # noqa: F401  (not needed; direct TCP below)
    except Exception:                                           # noqa: BLE001
        pass
    return server, port


class _Direct:
    """Minimal stack stub speaking plain TCP.

    connect() returns a reader/writer pair shaped like the tunnel's
    TcpConnection (open_service passes it as both reader and writer).
    """
    class Conn:
        """ shaped like the tunnel's TcpConnection: the same object serves
        as reader and writer (open_service passes it twice). """
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
            except Exception:                               # noqa: BLE001
                pass

        async def wait_closed(self):
            try:
                await self._writer.wait_closed()
            except Exception:                               # noqa: BLE001
                pass

    async def connect(self, host, port):
        reader, writer = await asyncio.open_connection(host, port)
        return _Direct.Conn(reader, writer)


async def _status(reply, services=None):
    server = await asyncio.start_server(
        _serve([("recv", None), ("send", reply)]), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        services = services or {"com.apple.mobile.lockdown.remote.trusted": {"Port": port}}
        return await devmode.status(_Direct(), "127.0.0.1", services)
    finally:
        server.close()
        await server.wait_closed()


async def _amfi(script, services=None):
    server = await asyncio.start_server(_serve(script), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        services = services or {"com.apple.amfi.lockdown.shim.remote": {"Port": port}}
        return server, services
    except Exception:                                           # noqa: BLE001
        server.close()
        await server.wait_closed()
        raise


async def main():
    assert await _status({"Value": True}) is True
    print("ok  status on")
    assert await _status({"Value": False}) is False
    print("ok  status off")
    assert await _status({"Error": "MissingValue"}) is None
    print("ok  status unreadable")
    assert await _status({"Value": "maybe"}) is None
    print("ok  status not boolean")

    try:
        await devmode.status(_Direct(), "127.0.0.1", {"other": {"Port": 1}})
    except devmode.DevmodeError as exc:
        assert "offers: other" in str(exc), exc
        print("ok  missing service names offers")
    else:
        raise AssertionError("missing service did not raise")

    # second lockdown name works
    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"Value": True})]), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await devmode.status(
            _Direct(), "127.0.0.1", {"com.apple.mobile.lockdown": {"Port": port}}) is True
        print("ok  lockdown fallback name")
    finally:
        server.close()
        await server.wait_closed()

    # show switch
    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"success": True})]), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        await devmode.show_switch(
            _Direct(), "127.0.0.1", {"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
        print("ok  show switch")
    finally:
        server.close()
        await server.wait_closed()

    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"Error": "Nope"})]), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        try:
            await devmode.show_switch(
                _Direct(), "127.0.0.1", {"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
        except devmode.DevmodeError as exc:
            assert "Nope" in str(exc), exc
            print("ok  show refused")
        else:
            raise AssertionError("refusal did not raise")
    finally:
        server.close()
        await server.wait_closed()

    # turn on: ok, passcode marker, other refusal
    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"success": True})]), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        await devmode.turn_on(
            _Direct(), "127.0.0.1", {"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
        print("ok  turn on")
    finally:
        server.close()
        await server.wait_closed()

    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"Error": "Device has a passcode set"})]),
        "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        try:
            await devmode.turn_on(
                _Direct(), "127.0.0.1", {"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
        except devmode.DevmodeError as exc:
            assert str(exc) == "passcode-set", exc
            print("ok  turn on passcode marker")
        else:
            raise AssertionError("passcode refusal did not raise")
    finally:
        server.close()
        await server.wait_closed()

    server = await asyncio.start_server(
        _serve([("recv", None), ("send", {"Error": "Denied"})]), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        try:
            await devmode.turn_on(
                _Direct(), "127.0.0.1", {"com.apple.amfi.lockdown.shim.remote": {"Port": port}})
        except devmode.DevmodeError as exc:
            assert "Denied" in str(exc), exc
            print("ok  turn on refused")
        else:
            raise AssertionError("refusal did not raise")
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
