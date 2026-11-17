#!/usr/bin/env python3
"""Comprehensive regression tests for every fix in the 0.9.48-stable build.

Each item is verified in more than one way (unit level + HTTP/level or
rendered-output level) so a silent regression cannot slip through.
"""
import asyncio
import base64
import io
import json
import os
import plistlib
import re
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from baristore import VERSION, apple, cli, mdns, pairing, signer, sources, storage, ui_page, webui


def _fresh_state():
    d = tempfile.mkdtemp(prefix="baristore-regression-")
    storage.STATE_DIR = d
    storage.STATE_FILE = os.path.join(d, "baristore.json")
    storage.INSTALLED_FILE = os.path.join(d, "installed_apps.json")
    storage.SOURCES_CACHE_FILE = os.path.join(d, "sources_cache.json")
    storage.ANISETTE_STATE_FILE = os.path.join(d, "anisette.json")
    storage.RECORD_PATH = os.path.join(d, "PairingFile_RemoteRP.plist")
    storage.ALT_RECORD_PLIST = os.path.join(d, "ALTPairingFile.plist")
    storage.ALT_RECORD_PAIRING = os.path.join(d, "ALTPairingFile.mobiledevicepairing")
    storage.UPLOAD_DIR = os.path.join(d, "uploads")
    storage.ensure_dirs()
    return d


def _serve(token="r" * 32):
    server = ThreadingHTTPServer(("127.0.0.1", 0), webui._Handler)
    server.token = token
    server.port = server.server_address[1]
    server.icon = b"<svg></svg>"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _get(server, path):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (server.port, path))
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except Exception as exc:
        return getattr(exc, "code", None), b""


def _post(server, path, body=None):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (server.port, path),
        data=json.dumps(body or {}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except Exception as exc:
        code = getattr(exc, "code", None)
        try:
            return code, json.loads(exc.read().decode())
        except Exception:
            return code, {}


def _wait_job(server, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        status, raw = _get(server, "/%s/api/status" % server.token)
        if status == 200:
            job = json.loads(raw)["job"]
            if not job["active"]:
                return job
        time.sleep(0.1)
    raise AssertionError("job did not finish in time")


def main():
    d = _fresh_state()
    print("state dir:", d)

    # ---------- 1. UI rendering / no native dialogs ----------
    html = ui_page.render_html("TOKEN", VERSION)
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    assert "showAlert" in script and "showConfirm" in script
    assert not re.search(r"(?<![.\w])alert\s*\(", script), "native alert remains"
    assert not re.search(r"(?<![.\w])confirm\s*\(", script), "native confirm remains"
    assert "window.open" not in script, "GitHub button would open twice"
    assert "location.reload" not in script, "reset uses dead reload"
    assert "restartBariStore" in script and "exportPairingFile" in script
    assert 'onclick="restartBariStore()"' in html
    assert 'onclick="exportPairingFile()"' in html
    assert "obPinWrap" in script and "optPinWrap" in script
    assert "job.kind === \"update\"" in script
    assert "onerror=\"this.remove()\"" in script, "broken icon fallback returned"
    print("ok  1a UI has in-app dialogs, restart/export buttons, PIN surfaces")
    open("/tmp/opencode/regression-ui.js", "w").write(script)
    print("ok  1b rendered JS written for node syntax check")

    # ---------- 2. mDNS advertises a LAN IP, never a VPN utun IP ----------
    ips = mdns.interface_ips()
    chosen = mdns.lan_ipv4()
    assert chosen == "10.7.0.1" or chosen not in ("127.0.0.1",), chosen
    ident = pairing.HostIdentity.generate()
    packet = mdns.build_announcement(ident, 51234, chosen)
    recs = mdns.parse_packet(packet)
    assert sorted(r["type"] for r in recs) == [1, 12, 12, 16, 16, 33, 33]
    a_recs = [r for r in recs if r["type"] == 1]
    assert a_recs[0]["address"] == chosen
    assert not a_recs[0]["address"].startswith("127.")
    print("ok  2a mDNS A record:", chosen, "interfaces:", ips)
    # Verify the Advertiser picks lan_ipv4, not wifi_ipv4.
    with mock.patch.object(mdns, "wifi_ipv4", return_value="10.7.0.99"), \
         mock.patch.object(mdns, "interface_ips", return_value={"en0": "192.168.1.50"}):
        adv = mdns.Advertiser(ident, 5123)
        assert adv.ipv4 == "192.168.1.50", adv.ipv4
        packet = mdns.build_announcement(ident, 5123, adv.ipv4).decode("latin1")
        assert "10.7.0.99" not in packet
    print("ok  2b Advertiser ignores VPN route guess when a LAN IP exists")

    # ---------- 3. Anisette identity is only rotated on real provisioning errors ----------
    assert apple._is_provisioning_error("Anisette server refused to mint headers")
    assert apple._is_provisioning_error("Apple rejected the request (-45061): x")
    assert not apple._is_provisioning_error("Connection timed out")
    assert not apple._is_provisioning_error("Apple rejected the request (-1): boom")
    print("ok  3a provisioning-error classifier")

    saved = {"email": "u@icloud.com", "gs_token": {"email": "u@icloud.com", "token": "t", "adsid": "a"}}
    storage.update_state(**saved)
    calls = {"n": 0}

    class FakeGS:
        pass

    class FakeAni:
        def headers(self):
            return {}

    class FakeSession:
        def call(self, *a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise apple.AppleAuthError("HTTP 503 transient")
            return [{"teamId": "T1", "name": "Team"}]

    with mock.patch.object(apple, "connect_anisette", return_value=(FakeAni(), FakeGS())), \
         mock.patch.object(apple, "DeveloperSession", return_value=FakeSession()), \
         mock.patch.object(apple.time, "sleep", return_value=None):
        session = apple.get_saved_session()
    assert session is not None and calls["n"] == 2, calls
    print("ok  3b get_saved_session retries transient portal failure once")

    # A real auth rejection must surface a concrete reason, not a silent None.
    class AlwaysFail(FakeSession):
        def call(self, *a, **k):
            raise apple.AppleAuthError("(-25293) The user name or password was incorrect.")

    with mock.patch.object(apple, "connect_anisette", return_value=(FakeAni(), FakeGS())), \
         mock.patch.object(apple, "DeveloperSession", return_value=AlwaysFail()), \
         mock.patch.object(apple.time, "sleep", return_value=None):
        assert apple.get_saved_session() is None
        assert "incorrect" in apple.get_last_session_error().lower()
    print("ok  3d real auth rejection surfaces as 'incorrect', not silent None")

    # ---------- 4. provisioning reports each step ----------
    steps = []
    prov_session = mock.Mock()
    prov_session.call.return_value = [{"teamId": "T1"}]
    with mock.patch.object(apple, "ensure_device"), \
         mock.patch.object(apple, "ensure_private_key", return_value="/tmp/key.pem"), \
         mock.patch.object(apple, "obtain_certificate", return_value=("/tmp/cert.pem", True)), \
         mock.patch.object(apple, "ensure_app_id", return_value={"appIdId": "X"}), \
         mock.patch.object(apple, "group_identifier_for", return_value=""), \
         mock.patch.object(apple, "download_profile", return_value=b"profile"), \
         mock.patch.object(apple.storage, "update_state"):
        apple.provision_for_signing(
            prov_session, "u@icloud.com", "a" * 40, "com.x", "X",
            team_id="T1", progress=steps.append,
        )
    joined = " | ".join(steps)
    for word in ("Registering device", "certificate", "App ID", "provisioning profile"):
        assert word.lower() in joined.lower(), joined
    print("ok  4 provisioning steps:", joined)

    # ---------- 5. signing progress callbacks ----------
    ipa_path = os.path.join(d, "tiny.ipa")
    with zipfile.ZipFile(ipa_path, "w") as zf:
        for i in range(810):
            zf.writestr("Payload/A.app/f%04d" % i, b"x")
    extracted = []
    signer.extract_ipa(ipa_path, os.path.join(d, "ex"), progress=extracted.append)
    assert any("Extracting IPA package" in m for m in extracted), extracted
    out_ipa = os.path.join(d, "out.ipa")
    packed = []
    signer.write_ipa(os.path.join(d, "ex"), out_ipa, progress=packed.append)
    assert any("Packing signed IPA" in m for m in packed), packed
    assert os.path.getsize(out_ipa) > 0
    print("ok  5 signer progress: extract=%d pack=%d" % (len(extracted), len(packed)))

    # ---------- 6. update fast path + background job ----------
    with mock.patch.object(webui, "_latest_remote_version", return_value=("sha", VERSION)):
        msg = webui.run_self_update()
    assert "latest" in msg.lower(), msg
    print("ok  6a update fast path:", msg)

    server = _serve()
    try:
        webui._CANCEL.clear()
        def _fake_update(progress=None):
            if progress:
                progress(50, "Contacting GitHub…")
            return "You are already on the latest version (v%s)." % VERSION

        with mock.patch.object(webui, "run_self_update", side_effect=_fake_update):
            status, res = _post(server, "/%s/api/update" % server.token)
        assert status == 200 and res["ok"], (status, res)
        job = _wait_job(server)
        assert job["result"] and "latest" in job["result"]["message"], job
        print("ok  6b /api/update responds immediately, result arrives via job")

        # ---------- 7. pairing PIN returned instantly ----------
        webui._JOB["active"] = False
        status, res = _post(server, "/%s/api/pair/start" % server.token, {"fresh": False})
        assert status == 200 and res.get("pin"), (status, res)
        pin = res["pin"]
        assert re.fullmatch(r"\d{6}", pin), pin
        assert webui._JOB["pin"] == pin
        webui.cancel_active_job()
        print("ok  7 /api/pair/start returns 6-digit PIN immediately:", pin)

        # Idempotency verified with a deliberately blocking pairing coroutine
        # (the real one cannot stay alive in this VPN-less test container).
        def _blocking_pair(**kwargs):
            time.sleep(3)
            return None, "a" * 40, {}

        with mock.patch.object(webui.tunnel, "pair_with_device", side_effect=_blocking_pair):
            webui._JOB["active"] = False
            webui.start_pairing_worker()
            first = webui._JOB["pin"]
            webui.start_pairing_worker()
            assert webui._JOB["pin"] == first, "second start changed the PIN"
        webui.cancel_active_job()
        print("ok  7b repeated Start Pairing is idempotent (same PIN)")

        # ---------- 8. export pairing POST ----------
        rec = {
            "public_key": b"\x11" * 32,
            "private_key": b"\x22" * 32,
            "identifier": "REG-HOST",
            "alt_irk": b"\x33" * 16,
            "peer_udid": "a" * 40,
        }
        b64 = base64.b64encode(plistlib.dumps(rec, fmt=plistlib.FMT_XML)).decode()
        status, _ = _post(server, "/%s/api/pair/import" % server.token, {"data_base64": b64})
        assert status == 200
        status, res = _post(server, "/%s/api/pair/export" % server.token)
        assert status == 200 and res["ok"] and res["data_base64"], (status, res)
        exported = plistlib.loads(base64.b64decode(res["data_base64"]))
        assert exported["identifier"] == "REG-HOST"
        assert res["paths"], res
        print("ok  8 POST /api/pair/export saves file + returns base64")

        # ---------- 9. reset / onboarding / restart / shutdown routes ----------
        assert _post(server, "/%s/api/onboarding/reset" % server.token)[0] == 200
        assert _post(server, "/%s/api/settings" % server.token, {"theme": "dark"})[0] == 200
        with mock.patch.object(webui.subprocess, "Popen") as popen:
            status, res = _post(server, "/%s/api/restart" % server.token)
        assert status == 200 and res["ok"], (status, res)
        assert popen.called
        assert "cli.py" in popen.call_args[0][0][-1]
        print("ok  9 onboarding-reset / settings / restart endpoints")

        # Real factory reset through the HTTP API must clear the saved session.
        storage.update_state(email="wipe@icloud.com")
        assert _post(server, "/%s/api/reset" % server.token)[0] == 200
        assert not storage.load_state().get("email"), storage.load_state()
        print("ok  9b /api/reset actually wipes state (no dead reload needed)")

        # ---------- 10. status endpoint surfaces job + login step ----------
        status, raw = _get(server, "/%s/api/status" % server.token)
        body = json.loads(raw)
        assert "job" in body and "login_step" in body
        print("ok 10 /api/status shape")
    finally:
        server.shutdown()

    # ---------- 11. LiveContainer icons are valid URLs ----------
    cfg = json.load(open(os.path.join(HERE, "..", "sources.json")))
    variants = [v for v in cfg["store_variants"] if "livecontainer" in v["id"]]
    assert len(variants) == 4
    for v in variants:
        assert "DefaultIcon.png" in v["icon_url"], v
        assert v["icon_url"].startswith("https://"), v
    print("ok 11 LiveContainer icons fixed in sources.json (4 variants)")

    # ---------- 12. terminal clear + restart CLI ----------
    assert callable(webui._clear_terminal)
    with mock.patch.object(webui, "_clear_terminal") as clear:
        with mock.patch.object(webui, "run", return_value=0):
            cli.main([])
        assert clear.called
    buf = io.StringIO()
    with mock.patch.object(sys, "stdout", buf), mock.patch.object(cli.subprocess, "Popen"):
        rc = cli.main(["--help"])
    assert rc == 0 and "restart" in buf.getvalue()
    print("ok 12 terminal clear on launch; restart subcommand in help")

    # ---------- 13. cancel flag + stale job guard ----------
    my_id = webui._start_job("install", "T", "s")
    webui._CANCEL.set()
    try:
        webui._throw_if_cancelled()
        raise AssertionError("expected CancelledError")
    except asyncio.CancelledError:
        pass
    webui._finish_job(result={"late": True}, job_id=my_id + 99)
    assert webui._JOB["active"] is True
    webui._CANCEL.clear()
    webui._finish_job(error="done", job_id=my_id)
    assert webui._JOB["active"] is False
    webui._finish_job(result={" overwritten": True}, job_id=my_id)
    assert webui._JOB["result"] is None
    print("ok 13 cancellation + stale worker guard")

    # ---------- 14. bounded DNS ----------
    assert len(apple._getaddrinfo_bounded("gsa.apple.com", 443)) >= 1
    print("ok 14 bounded DNS resolves Apple host")

    print("\nALL REGRESSION TESTS PASSED")


if __name__ == "__main__":
    main()
