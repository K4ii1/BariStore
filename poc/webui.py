#!/usr/bin/env python3
# =============================================================================
#  BariSign web UI (MIT) — one device, one page, no terminal strain.
#
#  Serves a page on this iPhone's loopback and opens it in a-Shell's internal
#  browser (a sheet over the terminal, so iOS never pauses us). The backend
#  runs the normal single-device pipeline in-process and the page only shows
#  steps, questions, the pairing PIN and a log. No build step, no dependency:
#  stdlib http.server + the engine already in poc/.
#
#  Security model (same as siboot's page, MIT): 127.0.0.1 only, a random port,
#  every path starts with 128 random bits that die with the run, the Host
#  header must name the loopback, answers are POSTed JSON. Closing the sheet
#  ends nothing by itself; Stop (or the end of the run) stops the server, and
#  with it the token.
#
#  UNVERIFIED ON A DEVICE: the sheet, the silent-audio keep-alive, the PIN hop
#  to Settings and back.
# =============================================================================

import asyncio
import html as _html
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
for _path in (_HERE,):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import pair_install


class FlowStop(Exception):
    """Stop button, or the page went away."""


_STATE = {
    "steps": [],            # [{id, label, state}] state: todo|active|done|error
    "activity": "",
    "progress": None,       # 0..100 or None
    "pin": None,
    "question": None,       # {id, kind, label, options} kind: text|secret|code|bool|choice
    "log": [],              # last 200 lines
    "done": None,           # {ok, title, lines}
    "audio": False,
    "keepalive": "—",
    "started": False,
}
_LOCK = threading.Lock()
_STOP = threading.Event()
_QUESTION = {"event": None, "answer": None}
_QID = [0]
_AUDIO_OK = {"event": None}
_LAST_POLL = {"at": 0.0}
_REV = {"n": 0}


def _bump_rev():
    with _LOCK:
        _REV["n"] += 1
_PIN_RE = re.compile(r"pairing code:\s*(\d{4,8})")
_PIN_LOG_RE = re.compile(r"(pairing code:\s*)\d{4,8}")

STEP_DEFS = [("requirements", "Requirements"), ("apple-id", "Apple ID"),
             ("variant", "Variant"), ("download", "Download"),
             ("portal", "Portal"), ("pairing", "Pairing"),
             ("developer-mode", "Developer Mode"), ("sign", "Sign"),
             ("install", "Install")]
_STEP_IDS = set(step_id for step_id, _label in STEP_DEFS)
_STAGE_ALIAS = {"apple sign-in": "apple-id"}


def _log_line(text):
    line = (text or "").rstrip("\n")
    if not line.strip():
        return
    line = _PIN_LOG_RE.sub(r"\1••••••", line)
    match = _PIN_RE.search(text or "")
    pin_changed = False
    with _LOCK:
        if match and _STATE["pin"] != match.group(1):
            _STATE["pin"] = match.group(1)
            pin_changed = True
    if pin_changed:
        _bump_rev()
    with _LOCK:
        _STATE["log"].append(line[-300:])
        del _STATE["log"][:-200]


class _WebLog:
    """sys.stdout for the flow thread: terminal stays clean, page gets all."""

    def write(self, text):
        if not text:
            return 0
        cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
        for part in cleaned.replace("\r", "\n").split("\n"):
            # Spinner rewrites one line: keep the newest segment only.
            segment = part.strip()
            if segment:
                _log_line(segment)
                activity = re.search(r"\(?\d+/\d+\)?\s*(.*)", segment)
                if activity and len(segment) < 120:
                    with _LOCK:
                        _STATE["activity"] = activity.group(0)[:100]
                percent = re.search(r"(\d{1,3})\s*%", segment)
                if percent:
                    with _LOCK:
                        try:
                            _STATE["progress"] = max(0, min(100, int(percent.group(1))))
                        except ValueError:
                            pass
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False


def _ask_web(label, kind="text", options=None, password_hint=""):
    if _STOP.is_set():
        raise FlowStop()
    with _LOCK:
        _QID[0] += 1
        _STATE["question"] = {"id": _QID[0], "kind": kind, "label": label,
                              "options": options or []}
        _QUESTION["event"] = threading.Event()
        _QUESTION["answer"] = None
    _bump_rev()
    event = _QUESTION["event"]
    while not _STOP.is_set():
        if event.wait(0.5):
            with _LOCK:
                answer = _QUESTION["answer"]
                _STATE["question"] = None
            _bump_rev()
            _log_line("%s %s" % (label, "••••••" if kind == "secret" else (answer or "")))
            return answer or ""
    raise FlowStop()


def _pick_team_web(session):
    """Team choice with real options (the vendored one only prints them)."""
    teams = session.call("listTeams", key="teams", device_type="")
    if not teams:
        raise RuntimeError("This Apple account has no developer team. Open "
                           "https://developer.apple.com in Safari, sign in once, "
                           "and accept the free developer agreement.")
    if len(teams) == 1:
        return teams[0]
    options = ["%s (%s)" % (team.get("name", "?"), team.get("teamId", "?"))
               for team in teams]
    answer = _ask_web("Which team should sign the app?", "choice", options)
    for index, team in enumerate(teams):
        if answer == options[index] or answer.strip() == str(index + 1):
            return team
    return teams[0]


def _heartbeat(text):
    """Activity pulse while waiting (pairing): proves we are alive."""
    stop = threading.Event()

    def _beat():
        waited = 0
        while not stop.wait(5):
            waited += 5
            if _STOP.is_set():
                return
            with _LOCK:
                _STATE["activity"] = "%s (%ds)" % (text, waited)

    thread = threading.Thread(target=_beat, daemon=True)
    thread.start()
    return stop.set


def _step_state(step_id, state):
    with _LOCK:
        for step in _STATE["steps"]:
            if step["id"] == step_id:
                step["state"] = state


def _patch_for_web(barisign, poc_login):
    """Route every prompt to the page. Terminal functions keep working behind."""
    import contextlib
    import io

    saved = {}

    def _ask(prompt, default=None):
        return _ask_web(prompt, "text")

    def _bool(prompt, default=False):
        answer = _ask_web(prompt, "bool")
        if not answer:
            return bool(default)
        return answer.strip().lower() in ("y", "yes", "1")

    def _yes(prompt, default=False):
        return _bool(prompt + (" [Y/n]" if default else " [y/N]"), default)

    def _read_line(prompt):
        kind = "code" if "code" in prompt.lower() else "text"
        return _ask_web(prompt, kind)

    def _read_password(prompt):
        return _ask_web(prompt, "secret")

    def _stage(title, lines=()):
        key = _STAGE_ALIAS.get(title.lower(), title.lower().replace(" ", "-"))
        if key in _STEP_IDS:
            with _LOCK:
                _STATE["activity"] = title
                _STATE["progress"] = None
            _step_state(key, "active")
        else:
            _log_line("== %s ==" % title)
            for line in lines:
                _log_line("  %s" % line)

    def _step(index, total, label):
        with _LOCK:
            _STATE["activity"] = "(%d/%d) %s" % (index, total, label)
        percent = re.search(r"(\d{1,3})\s*%", label)
        if percent:
            with _LOCK:
                _STATE["progress"] = max(0, min(100, int(percent.group(1))))

    def _done_line(label, text):
        _log_line("%s %s" % (label, text))

    for module, name, replacement in (
            (barisign, "_ask", _ask),
            (barisign, "_yes", _yes),
            (barisign, "_read_line", _read_line),
            (barisign, "_stage", _stage),
            (barisign, "_step", _step),
            (barisign, "_line_clear", lambda: None),
            (barisign, "_portal_line", lambda message, prefix="  ": _log_line("%s%s" % (prefix, message))),
            (barisign, "_portal_step", lambda message: _log_line("  %s" % message)),
            (barisign, "_portal_ask", lambda prompt, default=None: _ask_web(prompt, "text")),
            (barisign, "_portal_confirm", lambda prompt, default=False: _bool(prompt, default)),
            (barisign, "pick_team", _pick_team_web),
            (barisign, "_result", _done_line),
            (poc_login, "_read_password", _read_password),
            (pair_install, "_ask", lambda prompt, default="": _ask_web(prompt, "text")),
            (pair_install, "_read_line", lambda prompt: _ask_web(prompt, "text")),
            (pair_install, "_stage", _stage)):
        saved[(module, name)] = getattr(module, name)
        setattr(module, name, replacement)
    return saved


def _restore(saved):
    for (module, name), function in saved.items():
        try:
            setattr(module, name, function)
        except Exception:                                       # noqa: BLE001
            pass


def _pair_args(udid="", ipa="", pair_only=False):
    return {"ipa": ipa, "udid": udid, "host": "", "port": 0, "import": "",
            "target_ip": "", "loopback": True,
            "loopback_host": pair_install.LOOPBACK_HOST, "loopback_port": 0,
            "devmode": "", "no_devmode": False, "raw": False, "timeout": 300,
            "pair_only": pair_only, "repair": False, "debug": False, "export": ""}


def _wait_audio_ok(timeout=20):
    """True when the page confirmed silent audio is playing.

    Without confirmation the speech loop holds the app instead (the fallback
    when the sheet has no script or audio)."""
    event = threading.Event()
    with _LOCK:
        _AUDIO_OK["event"] = event
    try:
        stop_at = time.time() + timeout
        while time.time() < stop_at:
            if _STOP.is_set():
                raise FlowStop()
            if event.wait(0.5):
                return True
        return False
    finally:
        with _LOCK:
            _AUDIO_OK["event"] = None


def _run_flow():
    """The single-device pipeline. Runs in its own thread under _WebLog."""
    import contextlib
    import barisign
    import poc_login

    if _STATE["started"]:
        return
    with _LOCK:
        _STATE["started"] = True
        _STATE["steps"] = [{"id": step_id, "label": label, "state": "todo"}
                            for step_id, label in STEP_DEFS]
    saved = _patch_for_web(barisign, poc_login)
    out = _WebLog()
    old = sys.stdout
    sys.stdout = out
    try:
        _flow(barisign, poc_login)
    except FlowStop:
        with _LOCK:
            _STATE["done"] = {"ok": False, "title": "Stopped",
                              "lines": ["Nothing was half-installed. Run again any time."]}
    except Exception as exc:                                    # noqa: BLE001
        _log_line("FAILED %r" % (exc,))
        with _LOCK:
            _STATE["done"] = {"ok": False, "title": "Stopped with an error",
                              "lines": [str(exc)[:300],
                                        "The terminal behind this sheet has the full log."]}
    finally:
        sys.stdout = old
        _restore(saved)
        for step in _STATE["steps"]:
            with _LOCK:
                if step["state"] == "active":
                    step["state"] = "error" if _STATE["done"] and not _STATE["done"]["ok"] else "done"
        with _LOCK:
            if _STATE["done"] and _STATE["done"]["ok"]:
                for step in _STATE["steps"]:
                    step["state"] = "done"
            _STATE["audio"] = False


def _flow(barisign, poc_login):
    import devmode as devmode_module
    _step_state("requirements", "active")
    _log_line("Requirements: LocalDevVPN connected.")
    while not _STOP.is_set():
        if barisign._loopback_port():
            _log_line("LocalDevVPN answers.")
            break
        answer = _ask_web("LocalDevVPN is not answering. Connect it, then continue.",
                          "bool")
        if not answer:
            raise FlowStop()
    _step_state("requirements", "done")

    _step_state("apple-id", "active")
    email = (barisign.load_state().get("email") or "").strip()
    if not email:
        email = _ask_web("Apple ID", "text")
        if not email:
            raise FlowStop()
    session = barisign._login_session(email, staged=not barisign.load_state().get("email"))
    barisign.update_state(email=email)
    _step_state("apple-id", "done")

    variants = barisign.load_variants()
    if variants:
        options = [item["name"] for item in variants] + ["Custom IPA (from Files)"]
        answer = _ask_web("Which app?", "choice", options)
        picked = None
        for item in variants:
            if answer == item["name"]:
                picked = item
        state = barisign.load_state()
        if picked is not None:
            barisign.update_state(variant=picked["id"], bundle_id=picked["bundle_id"])
            _log_line("  %s" % picked["name"])
        else:
            chosen = barisign._choose_custom_ipa(state)
            if chosen is None:
                raise FlowStop()
    _step_state("variant", "done")

    ipa, info = barisign._obtain_ipa(barisign.load_state(), [])
    if not ipa:
        raise RuntimeError("download failed; see the log")
    if info.get("bundle_id"):
        if barisign._adopt_custom_bundle_id(info["bundle_id"]) is None:
            raise RuntimeError("custom bundle id refused")
    _step_state("pairing", "active")
    with _LOCK:
        _STATE["audio"] = True
        _STATE["keepalive"] = "page audio…"
    _log_line("Advertising as BariSign. Open Settings > Developer > "
              "Paired Macs on this iPhone and enter the printed PIN.")
    say_stop = None
    if not _wait_audio_ok():
        with _LOCK:
            _STATE["keepalive"] = "speech"
        _log_line("page audio not confirmed; speech fallback holds us")
        say_stop = pair_install.keep_awake_start()
    else:
        with _LOCK:
            _STATE["keepalive"] = "page audio"
    stop_beat = _heartbeat("waiting for the tap in Settings")
    try:
        state = barisign.load_state()
        code = asyncio.run(pair_install._run(
            _pair_args(udid=state.get("udid", ""), pair_only=True)))
    finally:
        stop_beat()
        with _LOCK:
            _STATE["audio"] = False
            pin_cleared = _STATE["pin"] is not None
            _STATE["pin"] = None
            _STATE["keepalive"] = "—"
    if pin_cleared:
        _bump_rev()
        if say_stop is not None:
            say_stop()
    if code != 0:
        raise RuntimeError("pairing step failed; see the log")
    _step_state("pairing", "done")

    _step_state("developer-mode", "active")
    _devmode_web()
    _step_state("developer-mode", "done")

    _step_state("portal", "active")
    state = barisign.load_state()
    result = barisign._portal(session, email, state.get("udid", ""),
                              state.get("bundle_id", ""), "BariSign device",
                              barisign.app_display_name(
                                  variant_id=state.get("variant", ""),
                                  bundle_id=state.get("bundle_id", "")))
    barisign.update_state(bundle_id=result["bundle_id"], team_id=result["team_id"],
                          profile=result["profile"], key=result["key"],
                          cert=result["cert"])
    _step_state("portal", "done")

    _step_state("sign", "active")
    state = barisign.load_state()
    saved_paths = barisign.signer.find_saved_paths(barisign.STATE_DIR)
    signed = barisign._sign_now(
        barisign.load_state().get("ipa") or ipa, saved_paths, [],
        hint=False, make_zip=False)
    if signed is None:
        raise RuntimeError("signing failed; see the log")
    _step_state("sign", "done")

    _step_state("install", "active")
    with _LOCK:
        _STATE["audio"] = True
        _STATE["keepalive"] = "page audio…"
    say_stop = None
    if not _wait_audio_ok():
        with _LOCK:
            _STATE["keepalive"] = "speech"
        _log_line("page audio not confirmed; speech fallback holds us")
        say_stop = pair_install.keep_awake_start()
    else:
        with _LOCK:
            _STATE["keepalive"] = "page audio"
    try:
        code = asyncio.run(pair_install._run(
            _pair_args(udid=barisign.load_state().get("udid", ""),
                       ipa=signed["ipa"])))
    finally:
        with _LOCK:
            _STATE["audio"] = False
            pin_cleared = _STATE["pin"] is not None
            _STATE["pin"] = None
            _STATE["keepalive"] = "—"
    if pin_cleared:
        _bump_rev()
        if say_stop is not None:
            say_stop()
    if code != 0:
        raise RuntimeError("install step failed; see the log")
    _step_state("install", "done")

    with _LOCK:
        _STATE["done"] = {
            "ok": True, "title": "Installed",
            "lines": ["On this iPhone: Settings > General > VPN & Device Management,",
                      "trust the developer, then open the app."]}


def _devmode_web():
    """Developer Mode gate inside the web flow: status, show, optional turn-on.

    One event loop for the whole gate: sessions die on restart, so the gate
    re-opens and re-checks instead of juggling sessions across loops.
    """
    import barisign
    import devmode as devmode_module
    import rpp_tunnel

    async def _seq():
        async def _open():
            record = rpp_tunnel.load_record(pair_install.RECORD_PATH)
            port = barisign._loopback_port()
            if not port:
                raise RuntimeError("LocalDevVPN stopped answering")
            return await pair_install.open_session(
                record, pair_install.LOOPBACK_HOST, port,
                barisign.load_state().get("udid", ""))

        async def _status(session):
            try:
                return await devmode_module.status(
                    session.stack, session.address, session.services)
            except Exception:                                   # noqa: BLE001
                return None

        async def _close(session):
            try:
                await session.close()
            except Exception:                                   # noqa: BLE001
                pass

        session = await _open()
        try:
            if await _status(session):
                _log_line("Developer Mode is on.")
                return
        finally:
            await _close(session)
        _log_line("Developer Mode is off or hidden; asking iOS to show the switch.")
        session = await _open()
        try:
            await devmode_module.show_switch(
                session.stack, session.address, session.services)
        except devmode_module.DevmodeError as exc:              # noqa: BLE001
            raise RuntimeError("could not show Developer Mode: %s" % exc)
        finally:
            await _close(session)
        choice = _ask_web("Turn it on now? (restarts this iPhone at once)",
                          "choice", ["Turn on now (restarts)", "I'll do it in Settings"])
        if (choice or "").startswith("Turn on"):
            session = await _open()
            try:
                try:
                    await devmode_module.turn_on(
                        session.stack, session.address, session.services)
                except devmode_module.DevmodeError as exc:      # noqa: BLE001
                    if str(exc) != "passcode-set":
                        raise RuntimeError("iOS refused: %s" % exc)
                    _log_line("Passcode is set: turn it on by hand in Settings.")
            finally:
                await _close(session)
            _ask_web("iPhone is restarting. When back, continue.", "bool")
        else:
            _ask_web("Turn ON Developer Mode in Settings (restart), then continue.",
                     "bool")
        session = await _open()
        try:
            on = await _status(session)
        finally:
            await _close(session)
        if not on:
            raise RuntimeError("Developer Mode is still off. Turn it on and run again.")
        _log_line("Developer Mode is on.")

    asyncio.run(_seq())


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
__META__
<title>BariSign</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 17px/1.45 -apple-system, "Segoe UI", sans-serif; margin: 0;
  padding: calc(1rem + env(safe-area-inset-top)) 1rem calc(2rem + env(safe-area-inset-bottom)); }
main { margin: 0 auto; max-width: 34rem; }
h1 { font-size: 1.5rem; margin: 0 0 .2rem; }
.sub { color: #666; margin: 0 0 1rem; }
ol.steps { list-style: none; margin: 0 0 1rem; padding: 0; }
ol.steps li { padding: .3rem .6rem; border-radius: .5rem; color: #666; }
ol.steps li.active { background: #0a6cff; color: #fff; font-weight: 600;
  animation: pulse 1.6s ease-in-out infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .55; } }
ol.steps li.done { color: #137333; }
ol.steps li.done::after { content: " ✓"; }
.card { border: 1px solid #ccc; border-radius: .8rem; padding: 1rem; margin: 0 0 1rem; }
.card h2 { font-size: 1.1rem; margin: 0 0 .5rem; }
.pin { font-size: 3.2rem; font-weight: 800; letter-spacing: .35rem; text-align: center;
  margin: .4rem 0; font-variant-numeric: tabular-nums; }
.hint { color: #666; font-size: .92rem; }
input[type=text], input[type=password], input[type=tel] { font: inherit; width: 100%;
  padding: .7rem; border: 1px solid #999; border-radius: .55rem; margin: .4rem 0 0; }
button { font: inherit; font-weight: 600; width: 100%; padding: .8rem; border: 0;
  border-radius: .55rem; background: #0a6cff; color: #fff; margin-top: .6rem; }
button.secondary { background: #e9e9ee; color: #000; }
.row { display: flex; gap: .6rem; } .row button { margin-top: .6rem; }
.bar { height: .5rem; background: #e0e0e6; border-radius: .25rem; overflow: hidden; margin-top: .6rem; }
.bar i { display: block; height: 100%; background: #0a6cff; }
.bar.indeterminate i { width: 30% !important;
  animation: slide 1.2s ease-in-out infinite alternate; }
@keyframes slide { from { margin-left: 0; } to { margin-left: 70%; } }
.log { border: 1px solid #ccc; border-radius: .8rem; padding: .6rem 1rem; margin: 0 0 1rem; }
.log pre { white-space: pre-wrap; word-break: break-word; font-size: .8rem;
  max-height: 16rem; overflow-y: auto; margin: .4rem 0 0; }
.stop { text-align: center; margin-top: 1.4rem; }
.err { color: #b00020; font-weight: 600; }
.ok { color: #137333; font-weight: 600; }
</style>
</head>
<body>
<main>
<h1>BariSign</h1>
<p class="sub">one iPhone, no computer. <span>keep-alive <span id="keepalive">__AUDIO__</span></span></p>
<ol class="steps" id="steps">__STEPS__</ol>
<div class="card"><h2 id="mtitle">__TITLE__</h2><div id="mactivity">__ACTIVITY__</div><div id="mbody">__BODY__</div></div>
<div class="log"><h3>Log</h3><pre id="log">__LOG__</pre></div>
<div class="stop">__STOP__</div>
</main>
<script>
"use strict";
const TOKEN = "__TOKEN__";
let lastRev = __REV__;
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
let audioStarted = false;
async function ensureAudio() {
  if (audioStarted) return;
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    if (!window.__ac) window.__ac = new AC();
    if (window.__ac.state === "suspended") await window.__ac.resume();
    const len = window.__ac.sampleRate * 2;
    const buf = window.__ac.createBuffer(1, len, window.__ac.sampleRate);
    buf.getChannelData(0).fill(0);
    if (!window.__asrc) {
      const src = window.__ac.createBufferSource();
      src.buffer = buf; src.loop = true; src.connect(window.__ac.destination); src.start();
      window.__asrc = src;
    }
    audioStarted = true;
    await fetch(TOKEN + "/api/audio", {method: "POST",
      headers: {"Content-Type": "application/json"}, body: "{}"});
  } catch (e) { /* without it the speech fallback holds us */ }
}
document.addEventListener("submit", () => { ensureAudio(); });
document.addEventListener("input", (e) => {
  const inp = e.target;
  if (inp && inp.matches && inp.matches('input[type="tel"][data-autosend]') &&
      inp.value.replace(/[^0-9]/g, "").length >= 6) inp.form.submit();
});
async function poll() {
  let st;
  try {
    const r = await fetch(TOKEN + "/api/state");
    st = await r.json();
  } catch (e) { return; }
  try {
    const steps = document.getElementById("steps");
    if (steps) steps.innerHTML = st.steps.map(x =>
      `<li class="${x.state}">${esc(x.label)}</li>`).join("");
    const ka = document.getElementById("keepalive");
    if (ka) ka.textContent = st.audio ? st.keepalive : "off";
    const pre = document.getElementById("log");
    if (pre) {
      const text = (st.log || []).join("\n");
      if (pre.textContent !== text) {
        const nearBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
        pre.textContent = text;
        if (nearBottom) pre.scrollTop = pre.scrollHeight;
      }
    }
    const act = document.getElementById("mactivity");
    if (act && st.activity !== undefined) act.textContent = st.activity || "";
    const bar = document.querySelector("#mbody .bar i");
    if (bar && typeof st.progress === "number")
      bar.style.width = Math.max(0, Math.min(100, st.progress)) + "%";
    if (st.audio) ensureAudio();
    if (st.rev !== lastRev) {
      lastRev = st.rev;
      try {
        const r = await fetch(TOKEN + "/api/panel");
        const p = await r.json();
        const t = document.getElementById("mtitle");
        const b = document.getElementById("mbody");
        if (t && p.title !== undefined) t.innerHTML = p.title;
        if (b && p.body !== undefined) {
          b.innerHTML = p.body;
          const inp = b.querySelector("input[type=text], input[type=password], input[type=tel]");
          if (inp) inp.focus();
        }
      } catch (e) { /* next poll retries */ }
    }
  } catch (e) { /* never break polling */ }
}
setInterval(poll, 1500);
poll();
</script>
</body>
</html>
"""


def _render_page(server):
    with _LOCK:
        steps = list(_STATE["steps"])
        activity = _STATE["activity"]
        progress = _STATE["progress"]
        pin = _STATE["pin"]
        question = dict(_STATE["question"]) if _STATE["question"] else None
        log = list(_STATE["log"])
        done = dict(_STATE["done"]) if _STATE["done"] else None
        audio = _STATE["audio"]
        keepalive = _STATE["keepalive"]
        started = _STATE["started"]
        polled = time.time() - _LAST_POLL["at"]
        rev = _REV["n"]
    token = server.token
    # Meta refresh only when the page script appears dead: with live JS
    # polling, reloads would wipe typed input.
    js_alive = started and not done and polled < 10
    steps_html = "".join(
        '<li class="%s">%s</li>' % (step["state"], _html.escape(step["label"]))
        for step in steps)
    log_html = _html.escape("\n".join(log[-30:]))
    audio_txt = keepalive if audio else "off"
    try:
        position = [step["state"] for step in steps].index("active") + 1
        counter = "step %d of %d \u00b7 " % (position, len(steps))
    except ValueError:
        counter = ""
    active_label = ""
    for step in steps:
        if step["state"] == "active":
            active_label = step["label"]
            break
    title, body, activity_text = _panel_parts(
        started, done, pin, question, activity, progress, counter, active_label)
    if question is not None or done is not None or not started:
        meta = ""
    elif not js_alive:
        meta = '<meta http-equiv="refresh" content="3">'
    else:
        meta = ""
    if done is not None or not started:
        stop = ""
    else:
        stop = ('<form method="post" action="api/stop">'
                '<button type="submit" class="secondary">Stop</button></form>')
    page = PAGE.replace("__TOKEN__", token)
    page = page.replace("__REV__", str(rev))
    page = page.replace("__META__", meta)
    page = page.replace("__AUDIO__", audio_txt)
    page = page.replace("__STEPS__", steps_html)
    page = page.replace("__TITLE__", title)
    page = page.replace("__ACTIVITY__", _html.escape(activity_text))
    page = page.replace("__BODY__", body)
    page = page.replace("__LOG__", log_html)
    page = page.replace("__STOP__", stop)
    return page.encode("utf-8")



def _panel_parts(started, done, pin, question, activity, progress,
                 counter, active_label):
    """Title + body for the main card. Used by the page and /api/panel."""
    if not started:
        title = "Ready"
        activity_text = ""
        body = ('<p class="hint">Runs the whole install on this iPhone: sign-in, '
                'download, pairing, Developer Mode, signing, install.</p>'
                '<form method="post" action="api/start" data-audio>'
                '<button type="submit">Start</button></form>')
    elif done:
        title = '<span class="%s">%s</span>' % ("ok" if done["ok"] else "err",
                                                _html.escape(done["title"]))
        activity_text = ""
        body = "".join("<p>%s</p>" % _html.escape(line) for line in done["lines"])
        body += ('<p class="hint">You can close this sheet. '
                 'Terminal: press Enter to finish.</p>')
    elif pin:
        title = "Enter this code"
        activity_text = "waiting for the tap in Settings…"
        body = ('<div class="pin">%s</div>'
                '<p class="hint">Settings &gt; Developer &gt; Paired Macs &gt; BariSign. '
                'This page keeps the app awake while you are over there.</p>') % _html.escape(pin)
    elif question:
        qid = question["id"]
        title = _html.escape(question["label"])
        activity_text = ""
        kind = question.get("kind")
        if kind == "bool":
            body = ('<form method="post" action="api/answer">'
                    '<input type="hidden" name="id" value="%d">'
                    '<div class="row"><button name="value" value="y">Yes</button>'
                    '<button name="value" value="" class="secondary">No</button></div>'
                    '</form>') % qid
        elif kind == "choice":
            body = "".join(
                '<form method="post" action="api/answer">'
                '<input type="hidden" name="id" value="%d">'
                '<button name="value" value="%s" class="secondary">%s</button></form>'
                % (qid, _html.escape(str(option), quote=True), _html.escape(str(option)))
                for option in (question.get("options") or []))
        else:
            ftype = {"secret": "password", "code": "tel"}.get(kind, "text")
            extra = (' inputmode="numeric" autocomplete="one-time-code" data-autosend'
                     if kind == "code" else "")
            body = ('<form method="post" action="api/answer">'
                    '<input type="%s" name="value"%s autocapitalize="off" autocorrect="off" spellcheck="false">'
                    '<input type="hidden" name="id" value="%d">'
                    '<button type="submit">Continue</button></form>') % (ftype, extra, qid)
    else:
        title = counter + _html.escape(active_label or "Working…")
        activity_text = activity or ""
        if progress is None:
            body = '<div class="bar indeterminate"><i></i></div>'
        else:
            body = '<div class="bar"><i style="width:%d%%"></i></div>' % progress
    return title, body, activity_text


class _Handler(BaseHTTPRequestHandler):
    server_version = "BariSignUI/1"

    def log_message(self, *args):                               # noqa: A003
        return

    def _json(self, status, value):
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _page(self):
        payload = _render_page(self.server)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self):
        location = "/" + self.server.token + "/"
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _guard(self):
        host = (self.headers.get("Host") or "")
        if host not in ("127.0.0.1:%d" % self.server.port, "localhost:%d" % self.server.port):
            return False
        if not self.path.startswith("/" + self.server.token + "/"
                                    ) and self.path != "/" + self.server.token:
            return False
        return True

    def do_GET(self):                                           # noqa: N802
        if not self._guard():
            self._json(404, {})
            return
        rest = self.path[len(self.server.token) + 1:]
        if rest in ("", "/"):
            self._page()
            return
        if rest == "/api/panel":
            with _LOCK:
                rev = _REV["n"]
            with _LOCK:
                snapshot = (dict(_STATE["done"]) if _STATE["done"] else None,
                            _STATE["pin"],
                            dict(_STATE["question"]) if _STATE["question"] else None,
                            _STATE["activity"], _STATE["progress"])
            done_snap, pin_snap, question_snap, activity_snap, progress_snap = snapshot
            with _LOCK:
                steps_snap = list(_STATE["steps"])
            try:
                position = [step["state"] for step in steps_snap].index("active") + 1
                counter_snap = "step %d of %d \u00b7 " % (position, len(steps_snap))
            except ValueError:
                counter_snap = ""
            active_label_snap = ""
            for step in steps_snap:
                if step["state"] == "active":
                    active_label_snap = step["label"]
                    break
            title, body, _activity_text = _panel_parts(
                True, done_snap, pin_snap, question_snap,
                activity_snap, progress_snap, counter_snap, active_label_snap)
            self._json(200, {"rev": rev, "title": title, "body": body})
            return
        if rest == "/api/state":
            with _LOCK:
                _LAST_POLL["at"] = time.time()
                self._json(200, {
                    "steps": [dict(step) for step in _STATE["steps"]],
                    "activity": _STATE["activity"],
                    "progress": _STATE["progress"],
                    "pin": _STATE["pin"],
                    "question": dict(_STATE["question"]) if _STATE["question"] else None,
                    "log": list(_STATE["log"]),
                    "done": dict(_STATE["done"]) if _STATE["done"] else None,
                    "audio": _STATE["audio"],
                    "keepalive": _STATE["keepalive"],
                    "started": _STATE["started"],
                    "rev": _REV["n"]})
            return
        self._json(404, {})

    def do_POST(self):                                          # noqa: N802
        if not self._guard():
            self._json(404, {})
            return
        rest = self.path[len(self.server.token) + 1:]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(max(0, min(length, 65536))).decode("utf-8", "replace")
        ctype = (self.headers.get("Content-Type") or "")
        try:
            body = json.loads(raw or "{}")
        except ValueError:
            body = {}
        if not isinstance(body, dict) or ("id" not in body and "value" not in body
                                          and "application/json" not in ctype):
            fields = urllib.parse.parse_qs(raw, keep_blank_values=True)
            body = {key: values[0] for key, values in fields.items()}
        wants_json = "application/json" in ctype or "application/json" in (
            self.headers.get("Accept") or "")

        def _answer(body):
            if rest == "/api/start":
                thread = threading.Thread(target=_run_flow, daemon=True)
                thread.start()
                return True
            if rest == "/api/stop":
                _STOP.set()
                with _LOCK:
                    if _QUESTION["event"] is not None:
                        _QUESTION["answer"] = ""
                        _QUESTION["event"].set()
                return True
            if rest == "/api/audio":
                with _LOCK:
                    if _AUDIO_OK["event"] is not None:
                        _AUDIO_OK["event"].set()
                return True
            if rest == "/api/answer":
                try:
                    answered = int(body.get("id", -1))
                except (TypeError, ValueError):
                    answered = -1
                with _LOCK:
                    question = _STATE["question"]
                if question and answered == question["id"]:
                    _QUESTION["answer"] = str(body.get("value", ""))
                    _QUESTION["event"].set()
                    return True
                return False
            return None

        outcome = _answer(body)
        if outcome is None:
            self._json(404, {})
        elif wants_json:
            self._json(200, {"ok": bool(outcome)})
        else:
            self._redirect()


def run():
    """Serve the page, open the sheet, run nothing until Start is tapped."""
    token = secrets.token_hex(16)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.token = token
    server.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = "http://127.0.0.1:%d/%s/" % (server.port, token)
    opened = False
    try:
        os.environ["BROWSER"] = "internalbrowser"
        opened = os.system("openurl %s" % url) == 0
    except Exception:                                           # noqa: BLE001
        opened = False
    print("BariSign %s" % _version())
    print("  page       %s" % url)
    if opened:
        print("  sheet      opened over the terminal")
    else:
        print("  ! sheet did not open; run this in a-Shell:")
        print("    BROWSER=internalbrowser openurl %s" % url)
    print("  tap Start on the page. Stop there (or Ctrl-C here) ends the run.")
    try:
        while not _STOP.is_set():
            _STOP.wait(1.0)
            with _LOCK:
                done = _STATE["done"] is not None and not _STATE["question"]
            if done:
                _STOP.wait(600)
                break
    except KeyboardInterrupt:
        print()
    finally:
        _STOP.set()
        server.shutdown()
    return 0


def _version():
    try:
        import barisign as _barisign
        return _barisign.VERSION
    except Exception:                                           # noqa: BLE001
        return "?"


if __name__ == "__main__":
    sys.exit(run())
