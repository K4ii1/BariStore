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


def test_pairing_target_paths():
    sidestore = pair_install.pairing_target("com.SideStore.SideStore.TEAMID")
    assert sidestore is not None
    documents_only, names = sidestore
    assert documents_only is True
    assert "ALTPairingFile.mobiledevicepairing" in names
    assert "PairingFile_RemoteRP.plist" in names
    live = pair_install.pairing_target("com.kdt.livecontainer.TEAMID")
    assert live is not None
    documents_only, names = live
    assert documents_only is False
    assert "SideStore/Documents/ALTPairingFile.mobiledevicepairing" in names
    assert "SideStore/Documents/PairingFile_RemoteRP.plist" in names
    altstore = pair_install.pairing_target("com.rileytestut.AltStore.TEAMID")
    assert altstore is not None
    documents_only, names = altstore
    assert documents_only is True
    assert names == ("ALTPairingFile.plist",)
    assert pair_install.pairing_target("com.rileytestut.AltStore.Beta.TEAMID") is None
    assert pair_install.pairing_target("com.example.Custom") is None


def test_remote_only_record():
    import plistlib
    import tempfile
    record = {"public_key": b"\x01" * 32, "private_key": b"\x02" * 32,
              "identifier": "HOST-1", "alt_irk": b"\x03" * 16,
              "host_identifier": "HOST-1", "peer_udid": "a" * 40}
    path = os.path.join(tempfile.mkdtemp(prefix="pairing-file-"), "record.plist")
    with open(path, "wb") as handle:
        handle.write(plistlib.dumps(record))
    data = pair_install._remote_only(path)
    parsed = plistlib.loads(data)
    assert set(parsed) == {"public_key", "private_key", "identifier", "alt_irk"}
    assert parsed["private_key"] == b"\x02" * 32


def test_registry():
    import plistlib
    import tempfile
    tmp = tempfile.mkdtemp(prefix="registry-")
    pair_install.REGISTRY_PATH = os.path.join(tmp, "paired_devices.json")
    pair_install.PAIRINGS_DIR = os.path.join(tmp, "pairings")
    real_save_state = pair_install.save_state
    pair_install.save_state = lambda **kwargs: {}
    try:
        assert pair_install.load_registry() == []
        record = {"private_key": b"\x01" * 32, "public_key": b"\x02" * 32,
                  "identifier": "HOST-1", "alt_irk": b"\x03" * 16,
                  "peer_udid": "a" * 40, "peer_name": "Phone",
                  "peer_model": "iPhone14,5", "peer_identifier": "PEER-1"}
        record_path = os.path.join(tmp, "record.plist")
        with open(record_path, "wb") as handle:
            plistlib.dump(record, handle)
        info = {"udid": "a" * 40, "name": "Phone", "model": "iPhone14,5",
                "identifier": "PEER-1"}
        entries = pair_install.registry_upsert(info, record_path, "192.168.1.20")
        assert len(entries) == 1 and entries[0]["udid"] == "a" * 40
        assert pair_install.load_registry()[0]["peer_ip"] == "192.168.1.20"
        second = os.path.join(tmp, "record2.plist")
        with open(second, "wb") as handle:
            plistlib.dump(dict(record, peer_udid="b" * 40, peer_name="Pad"), handle)
        info2 = {"udid": "b" * 40, "name": "Pad", "model": "iPad13,1",
                 "identifier": "PEER-2"}
        entries = pair_install.registry_upsert(info2, second, "192.168.1.21")
        assert [e["udid"] for e in entries] == ["b" * 40, "a" * 40]
        record2, udid2 = pair_install.registry_activate(entries[1])
        assert udid2 == "a" * 40
        assert record2["peer_name"] == "Phone"
    finally:
        pair_install.save_state = real_save_state
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
        record = {"peer_udid": "b" * 40, "peer_identifier": "MOCK"}
        status, payload = await pair_install.sweep_target(record, "b" * 40)
        assert status in ("match", "opens", "none"), (status, payload)
        device.server.close()
        await device.server.wait_closed()
    asyncio.run(main())


if __name__ == "__main__":
    test_id_match()
    print("ok  test_id_match")
    test_pairing_target_paths()
    print("ok  test_pairing_target_paths")
    test_remote_only_record()
    print("ok  test_remote_only_record")
    test_scan_and_probe()
    print("ok  test_scan_and_probe")
    test_registry()
    print("ok  test_registry")
