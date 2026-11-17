#!/usr/bin/env python3
"""Loopback probe + keep-awake fallback (Linux-testable halves).

The device halves (same-device Settings listing, LocalDevVPN answering,
speech holding the process) cannot run here; what CAN run here:
  * loopback_probe finds an open port and refuses a closed one;
  * keep_awake_start is a silent no-op where `say` is missing.
"""
import asyncio
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import pair_install


async def _probe_open():
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        found = await pair_install.loopback_probe("127.0.0.1", port)
        assert found == port, (found, port)
    finally:
        server.close()
        await server.wait_closed()


async def _probe_closed():
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    try:
        await pair_install.loopback_probe("127.0.0.1", port)
    except RuntimeError as exc:
        assert "LocalDevVPN" in str(exc), exc
        return
    raise AssertionError("closed port reported open")


def _keep_awake_noop():
    assert pair_install.shutil.which("say") is None, "say exists here; test assumes it does not"
    stop = pair_install.keep_awake_start()
    stop()


async def _probe_scan():
    # No explicit port: 49152 shut here, the 64-port scan finds nothing.
    try:
        await pair_install.loopback_probe("127.0.0.1", 0)
    except RuntimeError as exc:
        assert "LocalDevVPN" in str(exc), exc
        return
    raise AssertionError("expected no open port on 127.0.0.1:49152+")


def main():
    asyncio.run(_probe_open())
    print("ok  loopback explicit port")
    asyncio.run(_probe_closed())
    print("ok  loopback closed port")
    asyncio.run(_probe_scan())
    print("ok  loopback scan finds nothing")
    _keep_awake_noop()
    print("ok  keep-awake no-op without say")


if __name__ == "__main__":
    main()
