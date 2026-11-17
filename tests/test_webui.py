#!/usr/bin/env python3
"""Unit tests for the BariStore Web UI server and REST API endpoints."""
import base64
import json
import os
import plistlib
import sys
import tempfile
import threading
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from baristore import VERSION, storage, webui


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), webui._Handler)
    server.token = "t" * 32
    server.port = server.server_address[1]
    with open(os.path.join(HERE, "..", "baristore.svg"), "rb") as handle:
        server.icon = handle.read()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _get(server, path, host=None):
    request = urllib.request.Request("http://127.0.0.1:%d%s" % (server.port, path))
    if host is not None:
        request.add_header("Host", host)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except Exception as exc:
        return getattr(exc, "code", None), b""


def _post(server, path, body_dict):
    data = json.dumps(body_dict).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (server.port, path),
        data=data,
        headers={
            "Content-Type": "application/json",
            "Host": "127.0.0.1:%d" % server.port,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        code = getattr(exc, "code", None)
        try:
            err_body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            err_body = {}
        return code, err_body


def main():
    tmp_state = tempfile.mkdtemp(prefix="baristore-webui-test-")
    storage.STATE_DIR = tmp_state
    storage.STATE_FILE = os.path.join(tmp_state, "baristore.json")
    storage.INSTALLED_FILE = os.path.join(tmp_state, "installed_apps.json")
    storage.SOURCES_CACHE_FILE = os.path.join(tmp_state, "sources_cache.json")
    storage.RECORD_PATH = os.path.join(tmp_state, "PairingFile_RemoteRP.plist")
    storage.ALT_RECORD_PLIST = os.path.join(tmp_state, "ALTPairingFile.plist")
    storage.ALT_RECORD_PAIRING = os.path.join(tmp_state, "ALTPairingFile.mobiledevicepairing")
    storage.UPLOAD_DIR = os.path.join(tmp_state, "uploads")

    token = "t" * 32
    server = _serve()
    try:
        status, body = _get(server, "/%s/" % token)
        assert status == 200 and b"BariStore" in body, status
        assert b"Featured" in body and b"My Apps" in body and b"Options" in body
        print("ok  store UI page served")

        status, _ = _get(server, "/wrongtoken/")
        assert status == 404, status
        print("ok  wrong token -> 404")

        status, _ = _get(server, "/%s/api/status" % token, host="evil.example:80")
        assert status == 404, status
        print("ok  host header guard -> 404")

        status, icon_bytes = _get(server, "/%s/icon.svg" % token)
        assert status == 200 and icon_bytes.lstrip().startswith(b"<svg")
        print("ok  baristore.svg served")

        status, boot_raw = _get(server, "/%s/api/bootstrap" % token)
        assert status == 200
        boot = json.loads(boot_raw.decode("utf-8"))
        assert boot["ok"] is True
        assert boot["version"] == VERSION
        assert len(boot["catalog"]["store_variants"]) >= 7
        print("ok  /api/bootstrap returns store catalog & state")

        # Test pairing file import & export
        rec = {
            "public_key": b"\x11" * 32,
            "private_key": b"\x22" * 32,
            "identifier": "TEST-HOST-ID",
            "alt_irk": b"\x33" * 16,
            "peer_udid": "a" * 40,
        }
        rec_b64 = base64.b64encode(plistlib.dumps(rec, fmt=plistlib.FMT_XML)).decode()
        status, imp_res = _post(
            server, "/%s/api/pair/import" % token, {"data_base64": rec_b64}
        )
        assert status == 200 and imp_res["ok"] is True
        status, exp_bytes = _get(server, "/%s/api/pair/export" % token)
        assert status == 200
        exp_plist = plistlib.loads(exp_bytes)
        assert exp_plist["identifier"] == "TEST-HOST-ID"
        print("ok  /api/pair/import and /api/pair/export round-trip")

        # Test custom IPA upload & inspection
        ipa_buf = tempfile.NamedTemporaryFile(suffix=".ipa", delete=False)
        ipa_buf.close()
        with zipfile.ZipFile(ipa_buf.name, "w") as zf:
            zf.writestr(
                "Payload/TestApp.app/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.test.customapp",
                        "CFBundleDisplayName": "Custom Test App",
                        "CFBundleShortVersionString": "1.2.3",
                    },
                    fmt=plistlib.FMT_XML,
                ),
            )
        raw_ipa = open(ipa_buf.name, "rb").read()
        os.unlink(ipa_buf.name)
        status, up_res = _post(
            server,
            "/%s/api/ipa/upload" % token,
            {
                "filename": "TestApp.ipa",
                "data_base64": base64.b64encode(raw_ipa).decode(),
            },
        )
        assert status == 200 and up_res["ok"] is True
        assert up_res["ipa"]["bundle_id"] == "com.test.customapp"
        assert up_res["ipa"]["name"] == "Custom Test App"
        print("ok  /api/ipa/upload inspects custom IPA")

        # Test settings update & onboarding completion
        status, set_res = _post(
            server, "/%s/api/settings" % token, {"theme": "dark"}
        )
        assert status == 200 and set_res["state"]["theme"] == "dark"
        status, ob_res = _post(server, "/%s/api/onboarding/complete" % token, {})
        assert status == 200 and ob_res["ok"] is True
        print("ok  /api/settings and /api/onboarding/complete")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
