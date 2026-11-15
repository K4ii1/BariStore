#!/usr/bin/env python3
"""Unit tests for target discovery without Bonjour (Linux only)."""
import asyncio
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))
sys.path.insert(0, HERE)

import pair_install
import rpp_tunnel
import test_pair_tunnel


def test_id_match():
    assert pair_install._id_match("00008110-001431ea22eb601e",
                                  "00008110-001431EA22EB601E")
    assert pair_install._id_match("6ED01484-3C84-4CBE-BD38-16AF897697E4",
                                  "6ed01484-3c84-4cbe-bd38-16af897697e4")
    assert not pair_install._id_match("abc", "def")
    assert not pair_install._id_match("", "abc")
    assert not pair_install._id_match(None, "abc")


def test_scan_and_probe():
    async def main():
        device = test_pair_tunnel.MockDevice()
        port = await device.start()
        assert await pair_install._tcp_open("127.0.0.1", port) == port
        assert await pair_install._tcp_open("127.0.0.1", 1, timeout=0.5) is None
        found = await pair_install.scan_ports("127.0.0.1", start=port, count=2,
                                              timeout=1.0, batch=2)
        assert port in found
        peer = await rpp_tunnel.probe_handshake("127.0.0.1", port)
        assert peer.get("name") == "MockTarget"
        assert peer.get("udid") == "b" * 40
        assert peer.get("identifier") == "MOCK"
        assert await rpp_tunnel.probe_handshake("127.0.0.1", 1, timeout=1) is None
        device.server.close()
        await device.server.wait_closed()
    asyncio.run(main())


if __name__ == "__main__":
    test_id_match()
    print("ok  test_id_match")
    test_scan_and_probe()
    print("ok  test_scan_and_probe")
