#!/usr/bin/env python3
# =============================================================================
#  BariStore — Web UI Backend Server & Task Engine (MIT)
# =============================================================================

import asyncio
import base64
import json
import os
import plistlib
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import VERSION, apple, device, pairing, signer, sources, storage, tunnel, ui_page

_LOCK = threading.RLock()
_STOP = threading.Event()

_JOB = {
    "id": 0,
    "active": False,
    "kind": "",
    "title": "",
    "step": "",
    "progress": None,
    "pin": None,
    "error": None,
    "prompt": None,
    "result": None,
    "logs": [],
}
_ASYNC_TASK = {"loop": None, "task": None}


def _log(msg):
    text = str(msg or "").strip()
    if not text:
        return
    with _LOCK:
        _JOB["logs"].append(text[-300:])
        del _JOB["logs"][:-150]


# --- Keep-alive -------------------------------------------------------------
#
# Pairing needs one trip to Settings > Developer > Paired Macs, and iOS suspends
# a-Shell the moment the user leaves it. The only hold available to a Python
# guest inside a-Shell is audible speech through the `say` command (a-Shell sets
# the playback audio session at launch), so we keep saying one short line while
# a job runs. On Linux / CI `say` does not exist and this is a silent no-op.

_KEEPALIVE = {"stop": None, "thread": None}
_KEEPALIVE_TEXT = (
    "BariStore is waiting. Open Settings, Developer, Paired Macs, "
    "and enter the code shown on screen."
)


def keepalive_start():
    with _LOCK:
        if _KEEPALIVE["thread"] is not None and _KEEPALIVE["thread"].is_alive():
            return
        if shutil.which("say") is None:
            return
        stop = threading.Event()

        def _loop():
            while not stop.is_set():
                try:
                    process = subprocess.Popen(
                        ["say", "-r", "150", _KEEPALIVE_TEXT],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    return
                while process.poll() is None:
                    if stop.wait(0.4):
                        break
                if process.poll() is None:
                    try:
                        process.terminate()
                    except Exception:
                        pass
                if stop.wait(0.4):
                    return

        thread = threading.Thread(target=_loop, daemon=True)
        _KEEPALIVE["stop"] = stop
        _KEEPALIVE["thread"] = thread
        thread.start()


def keepalive_stop():
    with _LOCK:
        stop = _KEEPALIVE["stop"]
        _KEEPALIVE["stop"] = None
        _KEEPALIVE["thread"] = None
    if stop is not None:
        stop.set()


def _start_job(kind, title, step="Starting…"):
    with _LOCK:
        _JOB["id"] += 1
        _JOB["active"] = True
        _JOB["kind"] = kind
        _JOB["title"] = title
        _JOB["step"] = step
        _JOB["progress"] = None
        _JOB["pin"] = None
        _JOB["error"] = None
        _JOB["prompt"] = None
        _JOB["result"] = None
        _JOB["logs"] = []
        job_id = _JOB["id"]
    if kind in ("pair", "install", "refresh-all"):
        keepalive_start()
    return job_id


def _update_job(step=None, progress=None, pin=None):
    with _LOCK:
        if step is not None:
            _JOB["step"] = step
            _log(step)
        if progress is not None:
            _JOB["progress"] = max(0, min(100, int(progress)))
        if pin is not None:
            _JOB["pin"] = pin


def _finish_job(result=None, error=None, prompt=None):
    with _LOCK:
        _JOB["active"] = False
        _JOB["pin"] = None
        if error is not None:
            _JOB["error"] = str(error)
            _log("Error: %s" % error)
        if prompt is not None:
            _JOB["prompt"] = prompt
        if result is not None:
            _JOB["result"] = result
    keepalive_stop()


def cancel_active_job():
    with _LOCK:
        loop = _ASYNC_TASK["loop"]
        task = _ASYNC_TASK["task"]
    if loop is not None and task is not None:
        try:
            loop.call_soon_threadsafe(task.cancel)
        except Exception:
            pass
    _finish_job(error="Operation cancelled.")


def _run_coro(coro):
    loop = asyncio.new_event_loop()
    task = loop.create_task(coro)
    with _LOCK:
        _ASYNC_TASK["loop"] = loop
        _ASYNC_TASK["task"] = task
    try:
        return loop.run_until_complete(task)
    finally:
        with _LOCK:
            _ASYNC_TASK["loop"] = None
            _ASYNC_TASK["task"] = None
        loop.close()


# --- Environment & Onboarding Helpers ---------------------------------------

def probe_environment(check_tunnel=False):
    """Check LocalDevVPN, pairing record, and (optionally) Developer Mode over tunnel."""
    state = storage.load_state()
    vpn_port = tunnel.check_vpn_sync()
    vpn_connected = bool(vpn_port)
    paired = storage.has_pairing_record()
    udid = storage.normalise_udid(state.get("udid") or "")
    devmode = state.get("devmode_on")

    with _LOCK:
        busy = _JOB["active"]
    # Never open a second tunnel while a job already owns one: the pairing
    # listener must not be disturbed by a probe.
    if busy and check_tunnel:
        check_tunnel = False

    if check_tunnel and vpn_connected and paired:
        async def _check():
            async with await tunnel.open_session(port=vpn_port) as sess:
                status = await device.devmode_status(sess)
                return status, sess.udid, sess.product_type

        try:
            dm_status, tun_udid, model = _run_coro(_check())
            if tun_udid:
                udid = tun_udid
            if dm_status is not None:
                devmode = bool(dm_status)
                storage.update_state(devmode_on=devmode, udid=udid, peer_model=model)
        except Exception as exc:
            return {
                "vpn_connected": vpn_connected,
                "vpn_port": vpn_port,
                "paired": paired,
                "udid": udid,
                "devmode_on": devmode,
                "tunnel_error": str(exc),
            }

    return {
        "vpn_connected": vpn_connected,
        "vpn_port": vpn_port,
        "paired": paired,
        "udid": udid,
        "devmode_on": devmode,
        "tunnel_error": "",
    }


def start_pairing_worker(fresh_identity=False):
    with _LOCK:
        if _JOB["active"]:
            raise RuntimeError("Another operation is currently running.")
    _start_job("pair", "Device Pairing", "Preparing 3072-bit SRP & PIN…")

    def _worker():
        try:
            def on_pin(code):
                _update_job(
                    step="Open Settings > Developer > Paired Macs > BariStore and enter PIN",
                    pin=code,
                )

            def on_status(msg):
                _update_job(step=msg)

            _rec, udid, info = _run_coro(
                tunnel.pair_with_device(
                    timeout=300,
                    fresh_identity=fresh_identity,
                    on_pin=on_pin,
                    on_status=on_status,
                )
            )
            # Immediately verify tunnel & read UDID + Developer Mode status if VPN is active
            dm_status = None
            vpn_port = tunnel.check_vpn_sync()
            if vpn_port:
                _update_job(step="Verifying pairing tunnel & checking Developer Mode…")
                try:
                    async def _verify():
                        async with await tunnel.open_session(port=vpn_port) as sess:
                            dm = await device.devmode_status(sess)
                            if dm is False:
                                try:
                                    await device.devmode_show_switch(sess)
                                except Exception:
                                    pass
                            return sess.udid, sess.product_type, dm

                    tun_udid, model, dm_status = _run_coro(_verify())
                    if tun_udid:
                        udid = tun_udid
                    storage.update_state(
                        udid=udid,
                        paired=True,
                        devmode_on=dm_status,
                        peer_model=model or info.get("model", ""),
                    )
                except Exception as exc:
                    _log("Tunnel verification note: %s" % exc)

            _finish_job(
                result={
                    "paired": True,
                    "udid": udid,
                    "name": info.get("name") or "iPhone",
                    "model": info.get("model") or "",
                    "devmode_on": dm_status,
                }
            )
        except asyncio.CancelledError:
            _finish_job(error="Pairing cancelled.")
        except Exception as exc:
            _finish_job(error=str(exc))

    threading.Thread(target=_worker, daemon=True).start()


def handle_devmode_action(action):
    vpn_port = tunnel.check_vpn_sync()
    if not vpn_port:
        raise RuntimeError("LocalDevVPN is not connected. Connect LocalDevVPN first.")
    if not storage.has_pairing_record():
        raise RuntimeError("Device is not paired yet. Complete pairing first.")

    async def _act():
        async with await tunnel.open_session(port=vpn_port) as sess:
            if action == "status":
                dm = await device.devmode_status(sess)
                if dm is False:
                    try:
                        await device.devmode_show_switch(sess)
                    except Exception:
                        pass
                storage.update_state(devmode_on=dm)
                return {"devmode_on": dm, "switch_shown": dm is False}
            if action == "show":
                await device.devmode_show_switch(sess)
                return {
                    "switch_shown": True,
                    "message": "Developer Mode switch revealed in Settings > Privacy & Security > Developer Mode.",
                }
            if action == "on":
                try:
                    await device.devmode_turn_on(sess)
                    return {
                        "restarting": True,
                        "message": "Developer Mode enabled! Your iPhone will restart now. Re-open BariStore after reboot.",
                    }
                except device.DeviceServiceError as exc:
                    if str(exc) == "passcode-set":
                        await device.devmode_show_switch(sess)
                        return {
                            "restarting": False,
                            "passcode_set": True,
                            "switch_shown": True,
                            "message": "Because a passcode is set on this iPhone, iOS requires you to flip the switch manually in Settings > Privacy & Security > Developer Mode (revealed now).",
                        }
                    raise
        raise RuntimeError("Unknown Developer Mode action: %s" % action)

    return _run_coro(_act())


# --- Install & Refresh Worker -----------------------------------------------

def start_install_worker(params):
    """Run download -> portal provisioning -> signing -> loopback install in background."""
    with _LOCK:
        if _JOB["active"]:
            raise RuntimeError("Another install or pairing task is already running.")

    vpn_port = tunnel.check_vpn_sync()
    if not vpn_port:
        raise RuntimeError(
            "LocalDevVPN is not connected. Please open LocalDevVPN, connect the tunnel, and retry."
        )
    if not storage.has_pairing_record():
        raise RuntimeError("Pairing file is missing. Go to Options > Re-Pair Device first.")

    state = storage.load_state()
    email = (state.get("email") or "").strip()
    udid = storage.normalise_udid(state.get("udid") or "")
    if not email:
        raise RuntimeError("Not signed in to an Apple ID. Go to Options > Apple ID to sign in.")

    app_title = params.get("custom_name") or params.get("name") or "App"
    _start_job("install", "Installing %s" % app_title, "Checking requirements…")

    def _worker():
        try:
            kind = params.get("kind") or "altsource"
            local_ipa = params.get("local_ipa") or ""
            download_url = params.get("download_url") or ""
            expected_size = int(params.get("size") or 0)
            expected_sha256 = params.get("sha256") or ""
            version = params.get("version") or "1.0"
            icon_url = params.get("icon_url") or ""
            source_name = params.get("source_name") or "BariStore"
            base_bundle_id = (
                params.get("custom_bundle_id")
                or params.get("bundle_id")
                or ""
            ).strip()
            custom_name = (params.get("custom_name") or "").strip() or None
            drop_extensions = bool(params.get("drop_extensions"))
            drop_extension_folders = params.get("drop_extension_folders") or []
            reuse_full_bundle_id = (params.get("reuse_full_bundle_id") or "").strip()
            revoke_serial = (params.get("revoke_serial") or "").strip() or None

            # 1. Resolve variant if installing from built-in Stores & Containers
            if kind == "variant":
                variant_id = params.get("variant_id") or ""
                variants = sources.get_store_variants()
                variant = next((v for v in variants if v.get("id") == variant_id), None)
                if not variant:
                    raise RuntimeError("Unknown store variant: %s" % variant_id)
                _update_job(step="Resolving latest %s release from GitHub…" % variant["name"])
                resolved = sources.resolve_store_variant(variant)
                download_url = resolved["url"]
                expected_size = resolved["size"]
                expected_sha256 = resolved["sha256"]
                version = resolved["version"]
                icon_url = resolved.get("icon_url") or icon_url
                if not base_bundle_id:
                    base_bundle_id = resolved["bundle_id"]
                source_name = "Built-in Stores"

            # 2. Download or locate local IPA
            if local_ipa and os.path.isfile(local_ipa):
                ipa_path = local_ipa
            elif download_url:
                _update_job(step="Downloading %s (%s)…" % (app_title, version), progress=0)

                def _dl_prog(done, total):
                    if total > 0:
                        _update_job(progress=int(done * 45 / total))

                dest_name = "%s-%s.ipa" % (base_bundle_id or app_title, version)
                ipa_path = sources.download_ipa(
                    download_url,
                    dest_name,
                    expected_size=expected_size,
                    expected_sha256=expected_sha256,
                    progress=_dl_prog,
                )
            else:
                raise RuntimeError("No download URL or local IPA file provided.")

            # 3. Inspect IPA
            _update_job(step="Inspecting IPA package…", progress=48)
            inspected = signer.inspect_ipa(ipa_path)
            orig_bundle_id = inspected["bundle_id"]
            if not base_bundle_id:
                base_bundle_id = orig_bundle_id
            if not app_title or app_title == "App":
                app_title_resolved = custom_name or inspected["name"]
            else:
                app_title_resolved = app_title

            # 4. Authenticate Developer Portal session
            _update_job(step="Connecting to Apple Developer Portal…", progress=52)
            session = apple.get_saved_session()
            if session is None:
                raise RuntimeError(
                    "Your Apple ID session has expired. Please sign in again in Options > Apple ID."
                )

            # Ensure we have the device UDID
            current_udid = udid
            if not current_udid:
                async def _read_udid():
                    async with await tunnel.open_session() as sess:
                        return sess.udid
                current_udid = _run_coro(_read_udid())
                if not current_udid:
                    raise RuntimeError("Could not read device UDID over the tunnel.")

            # 5. Provision App ID, Certificate & Profile
            _update_job(step="Provisioning App ID & profile with Apple…", progress=60)
            try:
                prov = apple.provision_for_signing(
                    session,
                    email,
                    current_udid,
                    base_bundle_id,
                    app_title_resolved,
                    team_id=state.get("team_id") or "",
                    revoke_serial=revoke_serial,
                    reuse_full_bundle_id=reuse_full_bundle_id,
                )
            except apple.AppIdLimitReachedError as exc:
                _finish_job(
                    prompt={
                        "type": "appid_limit",
                        "message": str(exc),
                        "extensions": inspected.get("extensions") or [],
                        "existing_app_ids": [
                            {
                                "identifier": a.get("identifier", ""),
                                "name": a.get("name", ""),
                            }
                            for a in (exc.existing_app_ids or [])
                            if a.get("identifier")
                        ],
                        "retry_params": dict(params, local_ipa=ipa_path),
                    }
                )
                return
            except apple.CertLimitReachedError as exc:
                _finish_job(
                    prompt={
                        "type": "cert_limit",
                        "message": str(exc),
                        "certs": exc.certs,
                        "retry_params": dict(params, local_ipa=ipa_path),
                    }
                )
                return

            # 6. Sign the IPA
            _update_job(step="Signing %s on device…" % app_title_resolved, progress=70)
            signed_out = os.path.join(
                storage.SIGNED_DIR, "%s-signed.ipa" % prov["bundle_id"]
            )
            signed_info = signer.sign_ipa(
                ipa_path,
                prov["profile"],
                prov["key"],
                prov["cert"],
                output_ipa=signed_out,
                udid=current_udid,
                progress=lambda msg: _update_job(step=msg),
                drop_extensions=drop_extensions,
                drop_extension_folders=drop_extension_folders,
                custom_display_name=custom_name,
            )

            # 7. Upload & Install over Loopback Tunnel
            _update_job(step="Opening loopback tunnel to install…", progress=80)

            async def _do_install():
                async with await tunnel.open_session() as sess:
                    def _up_prog(sent, total):
                        if total > 0:
                            _update_job(
                                step="Uploading signed IPA (%d%%)…" % int(sent * 100 / total),
                                progress=80 + int(sent * 12 / total),
                            )

                    def _inst_log(line):
                        _update_job(step=line, progress=95)

                    await device.install_ipa(
                        sess,
                        signed_info["ipa"],
                        progress=_up_prog,
                        log=_inst_log,
                        auto_inject_pairing=True,
                    )

            _run_coro(_do_install())

            # 8. Record in installed_apps.json
            app_record = {
                "name": custom_name or params.get("name") or inspected["name"],
                "bundle_id": signed_info["bundle_id"],
                "base_bundle_id": base_bundle_id,
                "original_bundle_id": orig_bundle_id,
                "version": version or inspected["version"],
                "icon_url": icon_url,
                "source_name": source_name,
                "download_url": download_url,
                "local_ipa": ipa_path,
                "signed_ipa": signed_info["ipa"],
                "team_id": signed_info["team"],
                "expires_at": signed_info["expires_at"],
                "drop_extensions": drop_extensions,
                "has_pairing_support": device.pairing_target(signed_info["bundle_id"]) is not None,
            }
            storage.record_installed_app(app_record)
            _update_job(step="Installed %s!" % app_record["name"], progress=100)
            _finish_job(result={"installed": app_record})
        except asyncio.CancelledError:
            _finish_job(error="Installation cancelled.")
        except Exception as exc:
            _finish_job(error=str(exc))

    threading.Thread(target=_worker, daemon=True).start()


def start_refresh_all_worker():
    apps = storage.load_installed_apps()
    if not apps:
        raise RuntimeError("No installed apps to refresh.")
    with _LOCK:
        if _JOB["active"]:
            raise RuntimeError("Another operation is currently running.")

    vpn_port = tunnel.check_vpn_sync()
    if not vpn_port:
        raise RuntimeError("LocalDevVPN is not connected. Connect LocalDevVPN and retry.")

    state = storage.load_state()
    email = (state.get("email") or "").strip()
    udid = storage.normalise_udid(state.get("udid") or "")
    if not email:
        raise RuntimeError("Please sign in to your Apple ID first.")

    _start_job("refresh-all", "Refreshing %d Apps" % len(apps), "Connecting to Apple…")

    def _worker():
        try:
            session = apple.get_saved_session()
            if session is None:
                raise RuntimeError("Your Apple ID session expired. Sign in again in Options.")

            refreshed = []
            total_apps = len(apps)
            for idx, app in enumerate(apps, 1):
                name = app.get("name") or app.get("bundle_id")
                base_pct = int((idx - 1) * 100 / total_apps)
                _update_job(
                    step="(%d/%d) Refreshing %s…" % (idx, total_apps, name),
                    progress=base_pct,
                )
                ipa_path = app.get("local_ipa") or ""
                if not ipa_path or not os.path.isfile(ipa_path):
                    dl_url = app.get("download_url") or ""
                    if not dl_url:
                        _log("Skipping %s: source IPA not cached and no download URL." % name)
                        continue
                    ipa_path = sources.download_ipa(
                        dl_url, "%s-%s.ipa" % (app.get("base_bundle_id") or "app", app.get("version") or "1")
                    )

                prov = apple.provision_for_signing(
                    session,
                    email,
                    udid,
                    app.get("base_bundle_id") or app.get("original_bundle_id") or app.get("bundle_id"),
                    name,
                    team_id=state.get("team_id") or "",
                    reuse_full_bundle_id=app.get("bundle_id") or "",
                )
                signed_out = os.path.join(
                    storage.SIGNED_DIR, "%s-signed.ipa" % prov["bundle_id"]
                )
                signed_info = signer.sign_ipa(
                    ipa_path,
                    prov["profile"],
                    prov["key"],
                    prov["cert"],
                    output_ipa=signed_out,
                    udid=udid,
                    drop_extensions=bool(app.get("drop_extensions")),
                )

                async def _inst():
                    async with await tunnel.open_session() as sess:
                        await device.install_ipa(sess, signed_info["ipa"], auto_inject_pairing=True)

                _run_coro(_inst())
                updated = dict(app)
                updated["local_ipa"] = ipa_path
                updated["signed_ipa"] = signed_info["ipa"]
                updated["expires_at"] = signed_info["expires_at"]
                storage.record_installed_app(updated)
                refreshed.append(name)

            _update_job(step="Refreshed %d app(s)!" % len(refreshed), progress=100)
            _finish_job(result={"refreshed": refreshed})
        except Exception as exc:
            _finish_job(error=str(exc))

    threading.Thread(target=_worker, daemon=True).start()


# --- Self-Update Helper -----------------------------------------------------

def run_self_update():
    import re as _re
    repo = "barismd/BariStore"
    status, _h, body = apple.http_request(
        "GET",
        "https://github.com/%s/commits/main.atom" % repo,
        headers={"User-Agent": "BariStore"},
        timeout=20,
    )
    atom = (body or b"").decode("utf-8", "replace") if status == 200 else ""
    match = _re.search(r"commit/([0-9a-f]{40})", atom)
    base = (
        "https://raw.githubusercontent.com/%s/%s" % (repo, match.group(1))
        if match
        else "https://raw.githubusercontent.com/%s/main" % repo
    )
    status, _h, script_bytes = apple.http_request(
        "GET",
        base + "/install.sh",
        headers={"User-Agent": "BariStore", "Cache-Control": "no-cache"},
        timeout=35,
    )
    if status != 200 or not script_bytes:
        raise RuntimeError("Could not download update script (HTTP %d)." % status)

    fd, tmp = tempfile.mkstemp(prefix=".baristore-update-", dir=storage.ROOT)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(script_bytes)
        env = dict(os.environ)
        env["BARISTORE_DIR"] = storage.ROOT
        code = subprocess.call(["sh", tmp], env=env)
        if code != 0:
            raise RuntimeError("Update script exited with code %d." % code)
        return "Updated successfully! Restart BariStore to apply changes."
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# --- HTTP Request Handler ---------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "BariStore/1.0"

    def log_message(self, *args):
        return

    def _send_json(self, status, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_bytes(self, status, content_type, payload, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _guard(self):
        host = (self.headers.get("Host") or "").strip()
        allowed = (
            "127.0.0.1:%d" % self.server.port,
            "localhost:%d" % self.server.port,
        )
        if host not in allowed:
            return None
        prefix = "/" + self.server.token
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == prefix:
            return "/"
        if parsed.path.startswith(prefix + "/"):
            return parsed.path[len(prefix):]
        return None

    def _read_json_body(self, max_bytes=120 * 1024 * 1024):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > max_bytes:
            raise ValueError("Payload too large")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8", "replace"))

    def do_GET(self):  # noqa: N802
        route = self._guard()
        if route is None:
            self._send_json(404, {"error": "Not found"})
            return

        if route in ("/", "/index.html"):
            html_bytes = ui_page.render_html(self.server.token, VERSION).encode("utf-8")
            self._send_bytes(200, "text/html; charset=utf-8", html_bytes)
            return

        if route == "/icon.svg":
            icon = getattr(self.server, "icon", b"")
            if not icon:
                self._send_json(404, {})
                return
            self._send_bytes(200, "image/svg+xml", icon)
            return

        if route == "/api/status":
            with _LOCK:
                job_copy = dict(_JOB)
                job_copy["logs"] = list(_JOB["logs"][-40:])
            self._send_json(200, {"ok": True, "job": job_copy})
            return

        if route == "/api/bootstrap":
            state = storage.load_state()
            paired = storage.has_pairing_record()
            has_account = bool(
                state.get("email")
                and isinstance(state.get("gs_token"), dict)
                and state["gs_token"].get("token")
            )
            onboarding_complete = bool(
                state.get("onboarding_complete") or (paired and has_account)
            )
            catalog = sources.build_catalog_from_cache()
            with _LOCK:
                job_copy = dict(_JOB)
                job_copy["logs"] = list(_JOB["logs"][-40:])

            self._send_json(
                200,
                {
                    "ok": True,
                    "version": VERSION,
                    "onboarding_complete": onboarding_complete,
                    "state": {
                        "email": state.get("email") or "",
                        "has_session": has_account,
                        "team_id": state.get("team_id") or "",
                        "team_name": state.get("team_name") or "",
                        "udid": state.get("udid") or "",
                        "peer_name": state.get("peer_name") or "",
                        "peer_model": state.get("peer_model") or "",
                        "paired": paired,
                        "paired_at": state.get("paired_at") or 0,
                        "devmode_on": state.get("devmode_on"),
                        "theme": state.get("theme") or "system",
                        "anisette_url": state.get("anisette_url") or "",
                    },
                    "anisette_servers": apple.DEFAULT_ANISETTE_SERVERS,
                    "catalog": catalog,
                    "installed_apps": storage.load_installed_apps(),
                    "job": job_copy,
                },
            )
            return

        if route == "/api/check-env":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            deep = query.get("tunnel", ["0"])[0] == "1"
            self._send_json(200, {"ok": True, "env": probe_environment(check_tunnel=deep)})
            return

        if route == "/api/sources":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            force = query.get("refresh", ["0"])[0] == "1"
            catalog = sources.fetch_all_sources(force_refresh=force)
            self._send_json(200, {"ok": True, "catalog": catalog})
            return

        if route == "/api/apple/appids":
            try:
                session = apple.get_saved_session()
                if session is None:
                    self._send_json(400, {"ok": False, "error": "Not signed in or session expired."})
                    return
                team_id = storage.load_state().get("team_id") or ""
                app_ids, available, max_qty = apple.list_app_ids(session, team_id)
                certs = apple.list_ios_certs(session, team_id)
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "team_id": team_id,
                        "available": available,
                        "max": max_qty,
                        "app_ids": [
                            {
                                "id": a.get("appIdId", ""),
                                "identifier": a.get("identifier", ""),
                                "name": a.get("name", ""),
                                "expires": str(a.get("expirationDate") or ""),
                            }
                            for a in app_ids
                        ],
                        "certs": [
                            {
                                "serial": c.get("serialNumber", ""),
                                "name": c.get("name") or c.get("machineName") or "Development Certificate",
                                "machine": c.get("machineName") or "",
                                "expires": str(c.get("expirationDate") or ""),
                            }
                            for c in certs
                        ],
                    },
                )
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if route == "/api/pair/export":
            try:
                raw = storage.export_pairing_bytes()
                docs = os.path.join(os.path.expanduser("~"), "Documents")
                if os.path.isdir(docs):
                    out_file = os.path.join(docs, "BariStore-Pairing.mobiledevicepairing")
                    with open(out_file, "wb") as handle:
                        handle.write(raw)
                self._send_bytes(
                    200,
                    "application/x-apple-aspen-config",
                    raw,
                    extra_headers={
                        "Content-Disposition": 'attachment; filename="ALTPairingFile.mobiledevicepairing"'
                    },
                )
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"error": "Unknown endpoint"})

    def do_POST(self):  # noqa: N802
        route = self._guard()
        if route is None:
            self._send_json(404, {"error": "Not found"})
            return

        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": "Invalid request body: %s" % exc})
            return

        try:
            if route == "/api/job/cancel":
                cancel_active_job()
                self._send_json(200, {"ok": True})
                return

            if route == "/api/pair/start":
                start_pairing_worker(fresh_identity=bool(body.get("fresh")))
                self._send_json(200, {"ok": True})
                return

            if route == "/api/pair/import":
                b64_data = body.get("data_base64") or ""
                raw_bytes = base64.b64decode(b64_data) if b64_data else b""
                if not raw_bytes:
                    raise RuntimeError("Uploaded pairing file is empty.")
                parsed = plistlib.loads(raw_bytes)
                if not isinstance(parsed, dict):
                    raise RuntimeError("Invalid pairing plist format.")
                if parsed.get("host_identifier") and not parsed.get("identifier"):
                    parsed["identifier"] = parsed["host_identifier"]
                for req in ("private_key", "public_key", "identifier"):
                    if not parsed.get(req):
                        raise RuntimeError("Pairing file is missing '%s'." % req)
                storage.save_pairing_record(parsed)
                env = probe_environment(check_tunnel=True)
                self._send_json(200, {"ok": True, "env": env})
                return

            if route == "/api/devmode":
                action = (body.get("action") or "status").lower()
                res = handle_devmode_action(action)
                self._send_json(200, {"ok": True, "result": res})
                return

            if route == "/api/apple/login":
                res = apple.start_apple_login(
                    body.get("email", ""),
                    body.get("password", ""),
                    preferred_anisette=body.get("anisette_url", ""),
                )
                self._send_json(200, {"ok": True, "result": res})
                return

            if route == "/api/apple/2fa":
                res = apple.verify_apple_2fa(
                    body.get("login_id", ""),
                    body.get("code", ""),
                )
                self._send_json(200, {"ok": True, "result": res})
                return

            if route == "/api/onboarding/complete":
                storage.update_state(onboarding_complete=True)
                self._send_json(200, {"ok": True})
                return

            if route == "/api/sources/add":
                entry = sources.add_alt_source(body.get("url", ""), body.get("name", ""))
                catalog = sources.build_catalog_from_cache()
                self._send_json(200, {"ok": True, "source": entry, "catalog": catalog})
                return

            if route == "/api/sources/remove":
                sources.remove_alt_source(body.get("url", ""))
                catalog = sources.build_catalog_from_cache()
                self._send_json(200, {"ok": True, "catalog": catalog})
                return

            if route == "/api/sources/reset":
                sources.reset_default_sources()
                catalog = sources.fetch_all_sources(force_refresh=True)
                self._send_json(200, {"ok": True, "catalog": catalog})
                return

            if route == "/api/ipa/upload":
                filename = os.path.basename(body.get("filename") or "custom.ipa")
                b64_data = body.get("data_base64") or ""
                if not b64_data:
                    raise RuntimeError("No IPA file data received.")
                raw = base64.b64decode(b64_data)
                storage.ensure_dirs()
                safe_name = "%d-%s" % (int(time.time()), filename)
                if not safe_name.lower().endswith(".ipa"):
                    safe_name += ".ipa"
                dest = os.path.join(storage.UPLOAD_DIR, safe_name)
                with open(dest, "wb") as handle:
                    handle.write(raw)
                info = signer.inspect_ipa(dest)
                info["local_ipa"] = dest
                info["size"] = len(raw)
                self._send_json(200, {"ok": True, "ipa": info})
                return

            if route == "/api/install":
                start_install_worker(body)
                self._send_json(200, {"ok": True})
                return

            if route == "/api/apps/refresh-all":
                start_refresh_all_worker()
                self._send_json(200, {"ok": True})
                return

            if route == "/api/apps/delete":
                bundle_id = (body.get("bundle_id") or "").strip()
                if not bundle_id:
                    raise RuntimeError("Missing bundle_id.")
                vpn_port = tunnel.check_vpn_sync()
                if not vpn_port:
                    raise RuntimeError(
                        "LocalDevVPN is not connected. Connect LocalDevVPN to uninstall from device."
                    )

                async def _del():
                    async with await tunnel.open_session(port=vpn_port) as sess:
                        await device.uninstall_app(sess, bundle_id)

                _run_coro(_del())
                updated = storage.remove_installed_app(bundle_id)
                self._send_json(200, {"ok": True, "installed_apps": updated})
                return

            if route == "/api/apps/jit":
                bundle_id = (body.get("bundle_id") or "").strip()
                if not bundle_id:
                    raise RuntimeError("Missing bundle_id.")
                vpn_port = tunnel.check_vpn_sync()
                if not vpn_port:
                    raise RuntimeError(
                        "LocalDevVPN is not connected. Connect LocalDevVPN and retry Enable JIT."
                    )

                async def _jit():
                    async with await tunnel.open_session(port=vpn_port) as sess:
                        return await device.enable_jit(sess, bundle_id)

                res = _run_coro(_jit())
                self._send_json(200, {"ok": True, "result": res})
                return

            if route == "/api/apps/inject-pairing":
                bundle_id = (body.get("bundle_id") or "").strip()
                if not bundle_id:
                    raise RuntimeError("Missing bundle_id.")
                vpn_port = tunnel.check_vpn_sync()
                if not vpn_port:
                    raise RuntimeError(
                        "LocalDevVPN is not connected. Connect LocalDevVPN and retry."
                    )

                async def _inj():
                    async with await tunnel.open_session(port=vpn_port) as sess:
                        await device.write_pairing_file_to_app(sess, bundle_id)

                _run_coro(_inj())
                self._send_json(
                    200,
                    {"ok": True, "message": "Pairing file written into %s." % bundle_id},
                )
                return

            if route == "/api/settings":
                updates = {}
                if "theme" in body:
                    updates["theme"] = body["theme"]
                if "anisette_url" in body:
                    updates["anisette_url"] = (body["anisette_url"] or "").strip()
                if "team_id" in body:
                    updates["team_id"] = (body["team_id"] or "").strip()
                if updates:
                    storage.update_state(**updates)
                self._send_json(200, {"ok": True, "state": storage.load_state()})
                return

            if route == "/api/netcheck":
                results = apple.run_network_diagnostics()
                self._send_json(200, {"ok": True, "results": results})
                return

            if route == "/api/open-external":
                target = (body.get("url") or "").strip()
                if not target.startswith(("https://", "http://")):
                    raise RuntimeError("Only http(s) links can be opened.")
                environment = dict(os.environ)
                environment.pop("BROWSER", None)
                try:
                    subprocess.Popen(
                        ["openurl", target],
                        env=environment,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception as exc:
                    raise RuntimeError("Could not launch a browser: %s" % exc)
                self._send_json(200, {"ok": True, "url": target})
                return

            if route == "/api/update":
                msg = run_self_update()
                self._send_json(200, {"ok": True, "message": msg})
                return

            if route == "/api/cache/clear":
                count = storage.clear_cache()
                self._send_json(
                    200,
                    {"ok": True, "message": "Cleared %d cached file(s)." % count},
                )
                return

            if route == "/api/reset":
                storage.factory_reset()
                self._send_json(200, {"ok": True})
                return

            self._send_json(404, {"ok": False, "error": "Unknown POST endpoint"})
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})


def run(open_browser=True):
    """Start the local BariStore server and open the Web UI in a-Shell's internal browser."""
    token = secrets.token_hex(16)
    icon_path = os.path.join(storage.ROOT, "baristore.svg")
    try:
        with open(icon_path, "rb") as handle:
            icon = handle.read()
    except OSError:
        icon = b""

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.token = token
    server.port = server.server_address[1]
    server.icon = icon

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Warm up AltSources in a background thread so first launch has live apps ready quickly
    threading.Thread(
        target=lambda: sources.fetch_all_sources(force_refresh=False), daemon=True
    ).start()

    url = "http://127.0.0.1:%d/%s/" % (server.port, token)
    opened = False
    if open_browser:
        try:
            os.environ["BROWSER"] = "internalbrowser"
            opened = os.system("openurl %s" % url) == 0
        except Exception:
            opened = False

    print("BariStore %s" % VERSION)
    print("  url    %s" % url)
    if not opened and open_browser:
        print("  open   BROWSER=internalbrowser openurl %s" % url)
    print("  press Enter or Ctrl-C here to stop the server.")

    def _wait_enter():
        try:
            if sys.stdin and sys.stdin.isatty():
                input()
                _STOP.set()
        except Exception:
            pass

    threading.Thread(target=_wait_enter, daemon=True).start()
    try:
        while not _STOP.is_set():
            _STOP.wait(1.0)
    except KeyboardInterrupt:
        print()
    finally:
        _STOP.set()
        server.shutdown()
    return 0
