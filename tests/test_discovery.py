#!/usr/bin/env python3
"""Unit tests for pairing file targets, preferences merge, loopback probe, and multi-source AltSources."""
import asyncio
import os
import plistlib
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from baristore import device, sources, storage, tunnel


def test_pairing_target_paths():
    sidestore = device.pairing_target("com.SideStore.SideStore.TEAMID")
    assert sidestore is not None
    documents_only, names, prefs = sidestore
    assert documents_only is True
    assert "ALTPairingFile.mobiledevicepairing" in names
    assert "PairingFile_RemoteRP.plist" in names
    assert prefs == "Library/Preferences/com.SideStore.SideStore.TEAMID.plist"

    live = device.pairing_target("com.kdt.livecontainer.TEAMID")
    assert live is not None
    documents_only, names, prefs = live
    assert documents_only is False
    assert "Documents/ALTPairingFile.mobiledevicepairing" in names
    assert "SideStore/Documents/ALTPairingFile.mobiledevicepairing" in names
    assert prefs == "Documents/SideStore/Library/Preferences/com.SideStore.SideStore.plist"

    altstore = device.pairing_target("com.rileytestut.AltStore.TEAMID")
    assert altstore is not None
    documents_only, names, prefs = altstore
    assert documents_only is True
    assert names == ("ALTPairingFile.plist",)
    assert prefs is None

    stik = device.pairing_target("com.stik.stikdebug.TEAMID")
    assert stik is not None

    assert device.pairing_target("com.rileytestut.AltStore.Beta.TEAMID") is None
    assert device.pairing_target("com.example.Custom") is None


def test_merge_sidestored_prefs():
    merged = device.merge_sidestored_prefs(b"")
    parsed = plistlib.loads(merged)
    assert parsed == {"isPairingReset": False, "activePairingProtocol": "rppairing"}
    existing = plistlib.dumps(
        {"isPairingReset": True, "activePairingProtocol": "lockdown", "theme": "dark"},
        fmt=plistlib.FMT_XML,
    )
    merged = device.merge_sidestored_prefs(existing)
    parsed = plistlib.loads(merged)
    assert parsed["isPairingReset"] is False
    assert parsed["activePairingProtocol"] == "rppairing"
    assert parsed["theme"] == "dark"
    already = plistlib.dumps(
        {"isPairingReset": False, "activePairingProtocol": "rppairing"},
        fmt=plistlib.FMT_XML,
    )
    assert device.merge_sidestored_prefs(already) is None


def test_export_pairing_bytes():
    tmp = tempfile.mkdtemp(prefix="pairing-file-")
    old_rec = storage.RECORD_PATH
    storage.RECORD_PATH = os.path.join(tmp, "record.plist")
    try:
        record = {
            "public_key": b"\x01" * 32,
            "private_key": b"\x02" * 64,
            "host_identifier": "HOST-1",
            "host_alt_irk": b"\x03" * 16,
            "peer_udid": "a" * 40,
        }
        with open(storage.RECORD_PATH, "wb") as handle:
            handle.write(plistlib.dumps(record))
        data = storage.export_pairing_bytes()
        parsed = plistlib.loads(data)
        assert set(parsed) == {"public_key", "private_key", "identifier", "alt_irk"}
        assert parsed["private_key"] == b"\x02" * 32
        assert parsed["identifier"] == "HOST-1"
    finally:
        storage.RECORD_PATH = old_rec


def test_multi_source_deduplication():
    configured = [
        {"name": "Source One", "url": "https://one.example/apps.json", "custom": False},
        {"name": "Source Two", "url": "https://two.example/apps.json", "custom": True},
    ]
    raw_map = {
        "https://one.example/apps.json": {
            "fetched_at": 1000,
            "data": {
                "name": "Source One",
                "apps": [
                    {
                        "name": "RetroEmu",
                        "bundleIdentifier": "org.emu.retro",
                        "version": "1.0",
                        "downloadURL": "https://one.example/retro-1.0.ipa",
                        "size": 1024,
                    }
                ],
            },
        },
        "https://two.example/apps.json": {
            "fetched_at": 1000,
            "data": {
                "name": "Source Two",
                "apps": [
                    {
                        "name": "RetroEmu",
                        "bundleIdentifier": "org.emu.retro",
                        "version": "1.1",
                        "downloadURL": "https://two.example/retro-1.1.ipa",
                        "size": 2048,
                    }
                ],
            },
        },
    }
    catalog = sources.build_catalog_from_cache(configured, raw_map)
    assert len(catalog["apps"]) == 1
    app = catalog["apps"][0]
    assert app["bundle_id"] == "org.emu.retro"
    assert app["multi_source"] is True
    assert app["source_count"] == 2
    assert [o["source_name"] for o in app["offers"]] == ["Source One", "Source Two"]
    assert len(catalog["store_variants"]) >= 7


def test_sources_config_fallback():
    tmp = tempfile.mkdtemp(prefix="sources-cfg-")
    old = storage.SOURCES_CONFIG_FILE
    storage.SOURCES_CONFIG_FILE = os.path.join(tmp, "missing.json")
    try:
        config = sources.load_sources_config()
        assert len(config["store_variants"]) == 7, config["store_variants"]
        assert len(config["default_sources"]) >= 8, config["default_sources"]
        assert all(v.get("bundle_id") for v in config["store_variants"])
    finally:
        storage.SOURCES_CONFIG_FILE = old


def test_catalogue_tolerates_odd_shapes():
    """A third-party source may publish dicts where BariStore expects lists."""
    configured = [
        {"name": "Odd Source", "url": "https://odd.example/apps.json", "custom": True}
    ]
    raw_map = {
        "https://odd.example/apps.json": {
            "fetched_at": 1000,
            "data": {
                "name": {"unexpected": "dict"},
                "subtitle": ["nope"],
                "apps": [
                    {
                        "name": "Keyed",
                        "bundleIdentifier": "com.example.keyed",
                        "developerName": {"nested": True},
                        "iconURL": {"oops": 1},
                        "tintColor": 0,
                        "version": 1.4,
                        "size": "1,024",
                        "downloadURL": "https://odd.example/keyed.ipa",
                        # New AltStore sources key screenshots by device.
                        "screenshots": {
                            "iphone": ["https://odd.example/a.png", "https://odd.example/b.png"],
                            "ipad": [{"url": "https://odd.example/c.png"}],
                        },
                    },
                    {
                        "name": "Flat urls",
                        "bundleIdentifier": "com.example.flat",
                        "screenshotURLs": ["https://odd.example/d.png"],
                        "versions": [{"version": "2.0", "downloadURL": "https://odd.example/flat.ipa", "size": "2048"}],
                    },
                    {"bundleIdentifier": "com.example.nourl"},
                    "not a dict",
                ],
            },
        }
    }
    catalog = sources.build_catalog_from_cache(configured, raw_map)
    by_id = {a["bundle_id"]: a for a in catalog["apps"]}
    assert set(by_id) == {"com.example.keyed", "com.example.flat"}, by_id.keys()

    keyed = by_id["com.example.keyed"]
    assert keyed["name"] == "Keyed"
    assert keyed["version"] == "1.4"
    assert keyed["size"] == 1024
    assert keyed["developer"] == "Odd Source"
    assert keyed["icon_url"] == ""
    assert len(keyed["screenshots"]) == 3
    assert "https://odd.example/c.png" in keyed["screenshots"]

    flat = by_id["com.example.flat"]
    assert flat["screenshots"] == ["https://odd.example/d.png"]
    assert flat["size"] == 2048

    assert catalog["sources"][0]["name"] == "Odd Source"
    assert catalog["sources"][0]["subtitle"] == ""


def test_loopback_probe():
    async def main():
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            found = await tunnel.probe_loopback_port("127.0.0.1", port)
            assert found == port
        finally:
            server.close()
            await server.wait_closed()
        closed = await tunnel.probe_loopback_port("127.0.0.1", port)
        assert closed == 0

    asyncio.run(main())


if __name__ == "__main__":
    test_pairing_target_paths()
    print("ok  test_pairing_target_paths")
    test_merge_sidestored_prefs()
    print("ok  test_merge_sidestored_prefs")
    test_export_pairing_bytes()
    print("ok  test_export_pairing_bytes")
    test_multi_source_deduplication()
    print("ok  test_multi_source_deduplication")
    test_sources_config_fallback()
    print("ok  test_sources_config_fallback")
    test_catalogue_tolerates_odd_shapes()
    print("ok  test_catalogue_tolerates_odd_shapes")
    test_loopback_probe()
    print("ok  test_loopback_probe")
