#!/usr/bin/env python3
# =============================================================================
#  BariSign — on-device installer (MIT)
#
#  Runs on this iPhone (a-Shell). Single device: pairing, tunnel and install
#  all go through the LocalDevVPN loopback.
#
#      python3 -u poc/barisign.py            guided run
#      python3 -u poc/barisign.py udid       pair the target, save its UDID
#      python3 -u poc/barisign.py login      Apple sign-in
#      python3 -u poc/barisign.py portal     UDID + certificate + profile
#      python3 -u poc/barisign.py sign       download, sign and zip
#      python3 -u poc/barisign.py status     what is saved
#      python3 -u poc/barisign.py check      diagnostics only
#      python3 -u poc/barisign.py version    which copy is running
#      python3 -u poc/barisign.py forget     clear the saved state
# =============================================================================

import glob
import hashlib
import json
import os
import shlex
import shutil
import threading
import re
import plistlib
import subprocess
import sys
import time
import traceback
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (os.path.join(_HERE, "..", "third_party", "sideinstaller"),
                   os.path.join(_HERE, "third_party", "sideinstaller")):
    if os.path.isfile(os.path.join(_candidate, "portal.py")):
        sys.path.insert(0, _candidate)
        break
sys.path.insert(0, _HERE)

import poc_login                                              # noqa: E402  (sets up TLS trust)
import signin                                                 # noqa: E402
try:
    import portal                                             # noqa: E402
except ImportError as exc:                                    # noqa: BLE001
    print("Could not import the vendored developer-portal code: %s" % exc)
    print("third_party/sideinstaller/portal.py is missing or incomplete.")
    print("Fix it by re-running the installer in the BariSign folder:  sh install.sh")
    sys.exit(2)
from signin import AppleAccount, Fail, connect_anisette        # noqa: E402
from portal import (DeveloperSession, ensure_app_id, ensure_device,               # noqa: E402
                    ensure_private_key, obtain_certificate, pick_team,
                    download_profile, profile_plist, list_devices,
                    group_identifier_for, ensure_app_group)

# portal.py imported MACHINE_NAME by name, so both modules need it. It is what
# Apple shows next to a development certificate, and what lets a later run reuse
# the certificate this tool created instead of burning another slot.
signin.MACHINE_NAME = "BariSign"
portal.MACHINE_NAME = "BariSign"
try:
    import signer                                              # noqa: E402
    import download                                            # noqa: E402
except ImportError as exc:                                    # noqa: BLE001
    print("Could not import the signer or downloader module: %s" % exc)
    print("poc/signer.py or poc/download.py is missing or incomplete.")
    print("Fix it by re-running the installer in the BariSign folder:  sh install.sh")
    sys.exit(2)

VERSION = "0.9.25"
STATE_DIR = poc_login.POC_STATE
STATE_FILE = os.path.join(STATE_DIR, "barisign.json")
# Signed + downloaded IPAs live in one folder inside BariSign (tidy);
# custom inputs live in ~/Documents/Custom IPAs (outside, user-managed).
IPA_DIR = os.path.join(os.path.dirname(STATE_DIR), "ipa")
UNSIGNED_DIR = os.path.join(IPA_DIR, "unsigned")
SIGNED_DIR = os.path.join(IPA_DIR, "signed")
CUSTOM_IPA_DIR = os.path.join(os.path.expanduser("~"), "Documents", "Custom IPAs")
VARIANTS_FILE = os.path.join(_HERE, "..", "variants.json")

# Done here, not in main(): the key, certificate and profile paths are derived
# from it, and an early return in main() used to leave it pointing at the app
# container root, which is not writable.
os.makedirs(STATE_DIR, exist_ok=True)
try:
    # The drop folder must exist before the picker runs, or Files shows
    # nothing to drop into. Same reason as STATE_DIR: do it at import.
    os.makedirs(CUSTOM_IPA_DIR, exist_ok=True)
except OSError:
    pass
portal.STORAGE = STATE_DIR
signin.STORAGE = STATE_DIR


def _wire_progress():
    """The vendored stack narrates every step; it all goes through one line.

    portal.py imported info/step/warn/ask by name, so rebinding them in signin
    is not enough: its own references still printed straight to stdout and
    landed on top of the moving line.
    """
    for name in ("info", "ok", "step", "warn"):
        if hasattr(signin, name):
            setattr(signin, name, lambda message="", *a, **k: _activity(message))
    signin.PROGRESS = lambda message="": _activity(message)
    if "portal" in sys.modules:
        module = sys.modules["portal"]
        module.info = lambda message="", *a, **k: _portal_line(message)
        module.ok = lambda message="", *a, **k: _portal_line(message)
        module.warn = lambda message="", *a, **k: _portal_line(message, "  ! ")
        module.step = lambda message="", *a, **k: _portal_step(message)
        # Replace portal's ask/confirm with our own reader: input() inside the
        # vendored code kept losing the typed number to the moving line.
        module.ask = lambda prompt, default=None: _portal_ask(prompt, default)
        module.confirm = lambda prompt, default=False: _portal_confirm(prompt, default)
        original_revoke = module.revoke_to_make_room

        def portal_revoke(session, team):
            text = _SPINNER.text
            revoked = original_revoke(session, team)
            if revoked:
                # The certificate list and the prompt leave the screen full;
                # redraw the stage instead of continuing underneath them.
                _refresh_stage()
                if text:
                    _SPINNER.set(text)
            return revoked

        module.revoke_to_make_room = portal_revoke


_wire_progress()


# ---------------------------------------------------------------------------
# state: what the stages share with each other
# ---------------------------------------------------------------------------

def load_state():
    try:
        with open(STATE_FILE) as handle:
            state = json.load(handle)
    except Exception:                                         # noqa: BLE001
        return {}
    if not isinstance(state, dict):
        return {}
    # Bundle ids that were wrong in an earlier variants.json; fix silently
    # once so the portal stops registering the wrong App ID (AltStore Classic
    # is com.rileytestut.AltStore upstream, not com.altstore.AltStore).
    fixed = {"com.altstore.AltStore": "com.rileytestut.AltStore"}
    if state.get("bundle_id") in fixed:
        state["bundle_id"] = fixed[state["bundle_id"]]
        try:
            with open(STATE_FILE, "w") as handle:
                json.dump(state, handle, indent=2)
        except Exception:                                     # noqa: BLE001
            pass
    return state


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as handle:
        json.dump(state, handle, indent=2)


def update_state(**values):
    state = load_state()
    state.update(values)
    save_state(state)
    return state


def load_variants():
    try:
        with open(VARIANTS_FILE) as handle:
            return json.load(handle)["variants"]
    except Exception:                                         # noqa: BLE001
        return []


def app_display_name(variant_id="", bundle_id=""):
    """The App ID name shown in the Apple portal: the app's own name.

    The certificate keeps the BariSign name; the App ID carries e.g. SideStore,
    so the portal list stays readable when several apps are registered.
    """
    for item in load_variants():
        if variant_id and item.get("id") == variant_id:
            name = re.sub(r"\s*\(.*\)\s*$", "", item.get("name", "")).strip()
            if name:
                return name
        if bundle_id and item.get("bundle_id") == bundle_id:
            name = re.sub(r"\s*\(.*\)\s*$", "", item.get("name", "")).strip()
            if name:
                return name
    if bundle_id:
        return bundle_id.rsplit(".", 1)[-1]
    return "BariSign"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

# a-Shell runs SwiftTerm. 2J clears the visible page, 1;1H puts the cursor at the
# top: the same pair the app itself sends for Ctrl-L. 3J then drops the
# scrollback, because a-Shell restores the buffer on relaunch and the previous
# stage (the UDID instructions, for example) otherwise comes back. After a 3J the
# view's scroll offset can be stale, so a full page of newlines is printed first:
# that scrolls the buffer, lets the view follow to the bottom, and only then is
# the page cleared.
CLEAR = "\033[2J\033[1;1H"


def _clear_screen():
    """Clear the page and every saved line, and leave the view at the new page.

    Order matters. The previous stage is on the visible page; a page of newlines
    scrolls it into the saved lines, and only then does 3J drop them. 3J used to
    run first, so the stage that was just scrolled away was saved *after* the
    clear and stayed in the scrollback (sometimes, depending on what the buffer
    already held). A second page of newlines lets the view settle after 3J's
    buffer trim, then the page is cleared and the cursor homed.
    """
    try:
        import shutil
        rows = max(1, shutil.get_terminal_size((40, 24)).lines)
    except Exception:                                         # noqa: BLE001
        rows = 24
    # Two pages before 3J: the cursor can be anywhere on the page, so one page of
    # newlines does not always scroll a full screen (that is why the old stage
    # only sometimes ended up in the scrollback).
    sys.stdout.write("\033[0m" + "\n" * (2 * rows) + "\033[3J" + "\n" * rows + CLEAR)
    sys.stdout.flush()


def _columns():
    try:
        import shutil
        return max(20, shutil.get_terminal_size((40, 20)).columns)
    except Exception:                                         # noqa: BLE001
        return 40



class _Spinner:
    """One line, rewritten in place: '(2/5) device ....' with the dots growing."""

    def __init__(self):
        self.text = ""
        self.dots = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        # stop() retires the thread; a new stage needs a fresh one.
        if self._thread is None or not self._thread.is_alive():
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def set(self, text):
        with self._lock:
            self.text = text
            self.dots = 0
        self.start()

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                text = self.text
            if text:
                width = _columns() - 1
                sys.stdout.write("\r\033[2K" + ("  " + text + " " + "." * self.dots)[:width])
                sys.stdout.flush()
                with self._lock:
                    self.dots = (self.dots + 1) % 4
            # Wake every 50 ms so stop() can join without waiting a full tick.
            for _ in range(8):
                if self._stop.wait(0.05):
                    return

    def stop(self):
        self._stop.set()
        thread = self._thread
        if (thread is not None and thread.is_alive()
                and thread is not threading.current_thread()):
            # Join, not just signal: a thread woken mid-write could otherwise
            # erase the first characters of a prompt that follows.
            thread.join(0.7)
        with self._lock:
            self.text = ""
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()


_SPINNER = _Spinner()


_STAGE = {"title": "", "note": ""}


def _adopt_custom_bundle_id(bundle_id):
    """Point the state at a custom IPA's bundle id (True), or refuse (None).

    The portal signs profiles per bundle id, so a custom app needs its own App
    ID — which uses one of the free account's 10 slots. Adopting it into state
    keeps portal/sign/install consistent without extra flags.
    """
    state = load_state()
    if not bundle_id:
        return True
    if state.get("bundle_id") == bundle_id:
        return True
    if state.get("bundle_id"):
        print("  ! this IPA is %s" % bundle_id)
        print("    the saved profile is for %s" % state.get("bundle_id"))
        print("    run: sh barisign portal --bundle-id %s" % bundle_id)
        print("    (a custom App ID uses one of the 10 free slots)")
        return None
    update_state(bundle_id=bundle_id, variant="custom")
    print("  bundle   %s (custom)" % bundle_id)
    return True


def _stage(title, note=""):
    """Clean screen, then the stage header. The note restores what the clear
    would otherwise wipe (the Apple ID, for example)."""
    _STAGE["title"] = title
    _STAGE["note"] = note
    _SPINNER.stop()
    _clear_screen()
    print("BariSign %s" % VERSION)
    print()
    print("== %s ==" % title.upper())
    if note:
        print("  %s" % note)
    print()


def _refresh_stage():
    """Redraw the current stage after something scrolls a lot (a revoke)."""
    if _STAGE["title"]:
        _stage(_STAGE["title"], _STAGE["note"])
    else:
        _clear_screen()


def _step(index, total, label):
    _SPINNER.set("(%d/%d) %s" % (index, total, label))


def _activity(message):
    """Vendored narration would fight the spinner, so it is not shown."""
    return


def _portal_line(message, prefix="  "):
    """A portal line that would otherwise be written over the spinner.

    The spinner is left stopped: restarting it after every line of a burst (the
    certificate list) put a spinner frame between the lines and made the block
    look twice as long. The next _step, or the end of a prompt, resumes it.
    """
    _SPINNER.stop()
    print("%s%s" % (prefix, message))


def _portal_step(message):
    """Keep the stage number, replace the label: '(4/5) generating a key'."""
    text = _SPINNER.text
    prefix = ""
    if text.startswith("(") and ") " in text:
        prefix = text.split(") ", 1)[0] + ") "
    _SPINNER.set(prefix + message)


def _portal_read(prompt, default=None):
    """One line, read with the same byte reader as the 2FA code.

    input() here went through the vendored ask() while the spinner was running;
    the typed digits were wiped and the choice came back empty. This reads on a
    TTY byte by byte (visible, modes restored), and falls back to input() only
    when stdin is not a terminal.
    """
    if sys.stdin.isatty():
        answer = poc_login._masked_line(prompt, mask=False)
    else:
        try:
            answer = input(prompt)
        except EOFError:
            answer = ""
    answer = (answer or "").strip()
    if not answer and default is not None:
        return default
    return answer


def _portal_question(reader):
    """Stop the spinner, read with `reader`, then put the spinner back."""
    text = _SPINNER.text
    _SPINNER.stop()
    try:
        return reader()
    finally:
        if text:
            _SPINNER.set(text)


def _portal_ask(prompt, default=None):
    suffix = " [%s]: " % default if default else ": "
    return _portal_question(lambda: _portal_read(prompt + suffix, default))


def _portal_confirm(prompt, default=False):
    suffix = " [%s] " % ("Y/n" if default else "y/N")

    def read():
        answer = _portal_read(prompt + suffix, "").lower()
        if not answer:
            return default
        return answer in ("y", "yes")

    return _portal_question(read)


def _pause_for_input():
    _SPINNER.stop()


def _line_clear():
    _SPINNER.stop()


def _result(label, text):
    _line_clear()
    print()
    print("%s  %s" % (label, text))


def _read_line(prompt):
    """One line, read with our own byte reader on a TTY.

    input() stops working in a-Shell once _masked_line has touched the terminal's
    line discipline, and the UDID prompt runs right after the "Return to open
    Safari" prompt (which uses that reader). So every visible prompt reads bytes
    itself; non-TTY runs still use input() so piped input keeps working.
    """
    if sys.stdin.isatty():
        return poc_login._masked_line(prompt, mask=False)
    try:
        return input(prompt)
    except EOFError:
        return ""


def _ask(prompt, default=None):
    entered = (_read_line(prompt) or "").strip()
    return entered or (default or "")


def _yes(prompt, default=False):
    answer = _ask("%s [%s] " % (prompt, "Y/n" if default else "y/N")).lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def _bag_probe(gs, client_info, user_agent):
    """GET Apple's URL bag with the real anisette headers for this identity.

    No account data is involved. The probe carries the same headers the real bag
    request will, so a 200 here means the sign-in request will not be refused for
    this reason.
    """
    try:
        headers = gs.base_headers(plist=False)
    except Exception as exc:                                  # noqa: BLE001
        return 0, "no anisette headers: %r" % (exc,)
    headers["X-Mme-Client-Info"] = client_info
    headers["User-Agent"] = user_agent
    try:
        status, _, body = signin.request("GET", signin.GSA_URL_BAG,
                                         headers=headers, timeout=30)
    except Exception as exc:                                  # noqa: BLE001
        return 0, repr(exc)
    snippet = " ".join((body or b"").decode("utf-8", "replace").split())[:160]
    return status, snippet


def _preflight_apple(gs):
    """The exact first request the sign-in makes: Apple's URL bag, as a Mac.

    The identity is not a free choice, and that is why this probe tries exactly one:

      * the **URL bag** and the **2FA pages** only answer a Mac — asked as an Android
        phone the bag returns ten gsd.apple.com URLs and 2FA answers a bare 403;
      * the **sign-in POST** must claim Android, because public anisette servers mint
        their machine ID with Apple's Android ADI library, and since 2026-10-12
        GrandSlam refuses a sign-in whose client OS differs from it (-80045);
      * the **developer portal** is a third endpoint (Xcode's clientId), and it is
        still untested.

    So a 200 here means the bag — which every other call depends on — is reachable.
    Probing more identities would only add requests, not information.
    """
    status, note = _bag_probe(gs, signin.GSA_MAC_CLIENT_INFO, signin.GSA_USER_AGENT)
    return status == 200


def _sign_in(email, preferred=None, use_clipboard=False, staged=False):
    """Anisette, then Apple, then the password — never the other way round.

    Apple's October 2026 rules (verified against release notes, issue trackers and
    live servers): the sign-in must claim the platform the anisette data was made
    on, and only Mac anisette still signs in. So the Mac-emitting servers are tried
    first and their own client_info is what we send. A 503 or -80046 means the edge
    refused the identity: forget it and try the next server. The password is asked
    once, after Apple has answered, and never stored.

    `staged` says the caller already put up the Apple sign-in screen and asked for
    the address there; without it the address would be asked before the screen
    exists, which is what the UDID stage used to do.
    """
    if not staged:
        _stage("Apple sign-in", "Apple ID  %s" % email)
    state_path = os.path.join(STATE_DIR, "anisette.json")
    candidates = _anisette_order([preferred] if preferred else [])
    last_error = None
    saw_503 = False
    password = None

    def ask_code(label):
        """The 2FA code is not a secret: read it visibly, with our own echo, so it
        works even when the terminal's echo was left off by the password prompt."""
        # Same byte reader as every other prompt: the spinner is already
        # stopped here, and routing through _read_line keeps 2FA immune to
        # that whole class of terminal-mode bugs. Fresh line first: the iOS
        # system Allow/code popup can shift the view while it is up, so the
        # prompt must not share a line with anything. Empty returns (focus
        # jump, stray Return) re-prompt instead of sending a blank code to
        # Apple, which would burn the whole sign-in.
        _line_clear()
        print("  %s shown on your trusted device:" % label)
        while True:
            try:
                entered = "".join(ch for ch in _read_line("  code: ") if ch.isdigit())
            except KeyboardInterrupt:
                print()
                raise
            if len(entered) >= 6:
                print("  code entered (%d digits), checking with Apple..." % len(entered))
                return entered
            print("  ! that was %d digits; enter all 6" % len(entered))

    for index, url in enumerate(candidates, 1):
        _step(1, 3, "anisette")
        try:
            anisette, gs = connect_anisette(url, state_path)
        except Fail as exc:
            _line_clear()
            print("    unusable: %s" % exc)
            last_error = exc
            continue


        if _preflight_apple(gs):
            _step(2, 3, "apple reachable")
        else:
            _step(2, 3, "apple: retry")
            saw_503 = True
            last_error = Fail("HTTP 503 from Apple's edge")
            _forget_anisette(anisette, state_path)
            continue

        account = AppleAccount(email, gs, anisette)
        refused_identity = False
        for attempt in range(3):
            if password is None and use_clipboard:
                password = poc_login._clipboard_text().strip()
                if not password:
                    raise Fail("the clipboard is empty: copy the password first")
                _step(3, 3, "sign in")
                _pause_for_input()
            if password is None:
                _step(3, 3, "sign in")
                _pause_for_input()
                password = poc_login._read_password("  Password: ")
                if not password:
                    raise Fail("no password")
            try:
                account.login(password, ask_code)
                break
            except Fail as exc:
                last_error = exc
                message = str(exc)
                print("  ! %s" % message)
                if _identity_refused(message):
                    print("  ! identity refused; next server")
                    saw_503 = True
                    _forget_anisette(anisette, state_path)
                    refused_identity = True
                    break          # keep the password: it was never the problem
                if "rejected the verification code" in message:
                    # Wrong/expired code, not a wrong password: keep everything
                    # and ask for the code again instead of restarting login.
                    print("  ! code rejected; enter the current one")
                    if attempt < 2:
                        print("  retry %d/3" % (attempt + 2))
                        continue
                if "-22406" in message or "correct password" in message.lower():
                    print("  ! wrong password (-22406)")
                    print("    apple ID sent: %r" % email)
                    print("    password: %s" % poc_login._password_diagnostics(password))
                    password = None
                    if attempt < 2:
                        print("  retry %d/3" % (attempt + 2))
                        continue
                raise
        if refused_identity:
            continue
        password = None
        _line_clear()
        return account

    if not saw_503:
        raise Fail("no anisette server worked (last: %s)" % (last_error,))
    raise Fail("apple refused every identity (503); wait 10-15 minutes, \n"
               "    then run login again - the password was never the problem")


def _identity_refused(message):
    """True when Apple refused the *identity*, not the credentials.

    2026-10-12: a sign-in whose claimed platform differs from the anisette data is
    answered -80045. 2026-10-24: the Android claim itself is answered -80046, and
    some edges answer a bare HTTP 503 before reading the account. In all three
    cases the cure is another server and a fresh identity, never another password.
    """
    text = message.lower()
    return ("503" in text or "service unavailable" in text
            or "-80045" in text or "-80046" in text or "cannot be completed at this time" in text)


def _forget_anisette(anisette, state_path):
    try:
        anisette.forget_provisioning()
    except Exception:                                         # noqa: BLE001
        pass
    try:
        os.remove(state_path)
    except OSError:
        pass


def _reused_session(email):
    """A saved portal session that still works, or None.

    The portal token is a bearer credential like the signing key: it lives in
    state/ (sandboxed to a-Shell, wiped by forget/reset, never printed) and is
    validated live with listTeams before use. A dead token falls back to a
    full sign-in, so expiry just costs one extra Apple round-trip.
    """
    saved = load_state().get("gs_token") or {}
    if not isinstance(saved, dict):
        return None
    if (saved.get("email") or "") != email:
        return None
    token, adsid = saved.get("token") or "", saved.get("adsid") or ""
    if not token or not adsid:
        return None
    try:
        state_path = os.path.join(STATE_DIR, "anisette.json")
        _step(1, 3, "saved session")
        anisette, gs = connect_anisette("", state_path)
        session = DeveloperSession(AppleAccount(email, gs, anisette), token, adsid)
        session.call("listTeams", key="teams", device_type="")
    except Exception:                                       # noqa: BLE001
        _line_clear()
        return None
    _line_clear()
    return session


def _login_session(email, staged=False):
    """Portal session: the saved one when it still works, else a fresh sign-in."""
    session = _reused_session(email)
    if session is not None:
        print("  session    reused (no password, no 2FA needed)")
        return session
    account = _sign_in(email, staged=staged)
    token, adsid = account.app_token("xcode.auth")
    return DeveloperSession(account, token, adsid)


def _portal(session, email, udid, bundle_id, device_name, app_name):
    """Register the device, get a certificate and a provisioning profile."""
    # Also gives the revoke path a stage to redraw, with the Apple ID restored.
    _stage("Portal", "Apple ID  %s" % email)
    started = time.time()

    _step(1, 5, "team")
    team = pick_team(session)
    _step(2, 5, "device")
    ensure_device(session, team, udid, device_name)
    registered = list_devices(session, team)

    if not bundle_id:
        raise Fail("No bundle identifier, so there is nothing to register.")
    # state keeps the *full* identifier, so never append the team twice
    suffix = "." + team["teamId"]
    full_bundle_id = (bundle_id[:-len(suffix)] if bundle_id.endswith(suffix) else bundle_id) + suffix
    _step(3, 5, "app id")
    app_id = ensure_app_id(session, team, full_bundle_id, app_name)
    group_id = group_identifier_for(team, full_bundle_id, bundle_id)
    if group_id:
        try:
            ensure_app_group(session, team, app_id, group_id, app_name)
        except Fail as exc:                                       # noqa: BLE001
            # Free teams may not get app groups; the install still works and
            # the apps fall back to their own containers.
            _portal_line("no app groups for this team (%s); continuing without" % exc, "  ! ")

    key_path = ensure_private_key(email)
    _step(4, 5, "certificate")
    cert_path, reused = obtain_certificate(session, team, key_path, STATE_DIR)

    _step(5, 5, "profile")
    profile = download_profile(session, team, app_id)
    profile_path = os.path.join(STATE_DIR, "profile.mobileprovision")
    with open(profile_path, "wb") as handle:
        handle.write(profile)

    devices, expires = [], "?"
    try:
        parsed = profile_plist(profile)
        devices = parsed.get("ProvisionedDevices") or []
        expires = parsed.get("ExpirationDate", "?")
    except Exception:                                         # noqa: BLE001
        pass
    def _hex(value):
        return "".join(ch for ch in (value or "").lower() if ch in "0123456789abcdef")
    ours = any(_hex(device) == _hex(udid) for device in devices)
    _line_clear()
    print("  team      %s (%s)" % (team.get("name", "?"), team["teamId"]))
    print("  app id    %s" % full_bundle_id)
    print("  cert      %s" % ("reused" if reused else "created"))
    print("  devices   %d registered on this team, %d in the profile"
          % (len(registered), len(devices)))
    print("  profile   expires %s, target: %s"
          % (expires, "yes" if ours else "NO"))
    if len(registered) > len(devices):
        print("  ! the profile is older than the device list: run portal again")
    if devices and not ours:
        print("  ! the profile does not list the target: an app signed with it")
        print("    will not launch. Re-run portal, or remove the profile at")
        print("    developer.apple.com and run portal again.")
    print("  took      %.0f s" % (time.time() - started))

    try:
        update_state(gs_token={"email": email, "token": session.token,
                               "adsid": session.adsid, "saved_at": int(time.time())})
    except Exception:                                       # noqa: BLE001
        pass
    return {"team_id": team["teamId"], "bundle_id": full_bundle_id,
            "profile": profile_path, "key": key_path, "cert": cert_path}


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_check(_argv):
    """Everything that can be checked without an Apple ID."""
    passed = poc_login._selftest()
    print()
    print("CHECK  %s" % ("pass" if passed == 0 else "fail"))
    return passed


def cmd_version(_argv):
    """Which copy is running."""
    path = os.path.abspath(__file__)
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()[:12]
    _stage("Version")
    print("  file      %s" % path)
    print("  sha256    %s" % digest)
    return 0


def _have_command(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True
    return False


def cmd_status(_argv):
    state = load_state()
    _stage("Status")
    saved = state.get("gs_token") if isinstance(state.get("gs_token"), dict) else {}
    rows = (("Apple ID", state.get("email")), ("UDID", state.get("udid")),
            ("session", "saved" if saved.get("token") else "-"),
            ("variant", state.get("variant")), ("release", state.get("asset_version")),
            ("bundle", state.get("bundle_id")), ("team", state.get("team_id")),
            ("cert", state.get("cert")), ("profile", state.get("profile")),
            ("ipa", _display_path(state["ipa"]) if state.get("ipa") else None),
            ("signed", _display_path(state["signed_ipa"]) if state.get("signed_ipa") else None),
            ("zip", _display_path(state["zip"]) if state.get("zip") else None))
    for label, value in rows:
        print("  %-9s %s" % (label, value or "-"))
    return 0


def cmd_forget(_argv):
    if os.path.isfile(STATE_FILE):
        os.remove(STATE_FILE)
        print("forgot: Apple ID, UDID, variant, certificate, profile")
    else:
        print("nothing saved")
    return 0


def cmd_reset(_argv):
    """Remove everything this tool created; leave the installed program alone."""
    _stage("Reset")
    folder = os.path.dirname(STATE_DIR)
    folders = []
    files = []
    if os.path.isdir(STATE_DIR) and os.listdir(STATE_DIR):
        folders.append(STATE_DIR)
    folders.extend(sorted(glob.glob(os.path.join(folder, ".barisign-sign-*"))))
    for variant in load_variants():
        identifier = variant.get("id")
        if identifier:
            for directory in (folder, IPA_DIR, UNSIGNED_DIR):
                path = os.path.join(directory, identifier + ".ipa")
                if os.path.isfile(path):
                    files.append(path)
    for pattern in ("*-signed.ipa", "*-signed.zip", "*.ipa.part", "*.zip.part"):
        files.extend(sorted(glob.glob(os.path.join(folder, pattern))))
        files.extend(sorted(glob.glob(os.path.join(SIGNED_DIR, pattern))))
    files = sorted(set(files))

    if not folders and not files:
        _result("RESET", "nothing to remove")
        return 0

    _line_clear()
    if os.path.isdir(STATE_DIR):
        print("  state     Apple ID, UDID, key, certificate, profile")
    if files:
        print("  files     %d downloaded or signed file%s"
              % (len(files), "" if len(files) == 1 else "s"))
    if len(folders) > 1:
        print("  temp      %d working folder%s"
              % (len(folders) - 1, "" if len(folders) == 2 else "s"))
    print()
    if not _yes("  delete these?", False):
        print("  nothing removed")
        return 0

    removed = 0
    for path in folders:
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    for path in files:
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
    _result("RESET", "ok  %d removed" % removed)
    return 0


UDID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{24})$")


ANSI_ESCAPES = re.compile(r"\x1b\[[0-9;?]*[A-Za-z~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Z0-9]")


def extract_udid(text):
    """Find a UDID inside whatever arrived.

    a-Shell may hand us a bracketed paste ("\x1b[200~…\x1b[201~"), a labelled line
    ("UDID: …"), quotes, or plain text. Rather than rejecting all of that, strip the
    terminal noise and pick the UDID out of it. Returns the canonical form or "".
    """
    cleaned = ANSI_ESCAPES.sub("", text or "")
    cleaned = "".join(ch for ch in cleaned if ch.isalnum() or ch in "-_ ")
    # "UDID: 00008110 001a …" — drop the label, then glue groups of hex together
    unlabelled = re.sub(r"^\s*udid\s*[:=]?\s*", "", cleaned, flags=re.IGNORECASE)
    squashed = unlabelled
    while True:
        tighter = re.sub(r"(?<=[0-9a-fA-F])[ \-_](?=[0-9a-fA-F])", "", squashed)
        if tighter == squashed:
            break
        squashed = tighter
    for candidate in (cleaned, unlabelled, squashed):
        for pattern in (r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])",
                        r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{16}(?![0-9a-fA-F])",
                        r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])"):
            found = re.search(pattern, candidate)
            if found:
                return normalise_udid(found.group(0))
    return ""


def normalise_udid(text):
    """Accept what a UDID page copies: 40 hex characters, or the 8+16 form that
    A12-and-later devices use, with or without the dash."""
    cleaned = re.sub(r"[\s\-]", "", (text or "")).lower()
    if not UDID_PATTERN.match(cleaned):
        return ""
    if len(cleaned) == 40:
        return cleaned
    return "%s-%s" % (cleaned[:8], cleaned[8:])




def cmd_udid(argv):
    """Get the target device's UDID from pairing (no page anymore)."""
    typed = [item for item in argv if not item.startswith("-")]
    udid = extract_udid(typed[0]) if typed else ""
    for flag in ("--manual", "--no-open", "--page"):
        if flag in argv:
            print("  ! the UDID page is gone; pairing gives the UDID now")
            break
    # No stage header here: the pair subprocess owns the screen from here.
    if not udid:
        print("  Pairing the TARGET; the pairing gives its UDID.")
        print("  If Paired Macs shows nothing, the target needs")
        print("  Developer Mode first (guided run walks you through it).")
        print()
        pair = os.path.join(_HERE, "pair_install.py")
        code = subprocess.call([sys.executable, "-u", pair, "--pair-only",
                                "--timeout", "180"])
        udid = extract_udid(load_state().get("udid", ""))
        if code != 0 or not udid:
            print("  pairing did not return a UDID")
            print("  turn on Developer Mode on the target, then run again")
            return 1

    update_state(udid=udid, paired_at=int(time.time()))
    _result("UDID", "%s saved" % udid)
    return 0


PAIRING_FRESH_SECS = 1800


def _ensure_udid(loopback=False):
    """UDID from state, or pair for it now (loopback for the one-device flow).

    Portal needs the UDID before the pair stage runs, so this is the pairing
    that happens inside the portal stage. Returns "" when pairing failed.
    """
    udid = normalise_udid(load_state().get("udid", ""))
    if udid:
        return udid
    if loopback:
        pair = os.path.join(_HERE, "pair_install.py")
        code = subprocess.call([sys.executable, "-u", pair, "--loopback",
                                "--pair-only", "--keep-awake"])
        if code != 0:
            return ""
        return normalise_udid(load_state().get("udid", ""))
    print("no UDID: running udid first")
    if cmd_udid([]) != 0:
        return ""
    return normalise_udid(load_state().get("udid", ""))


def _ensure_pairing(loopback=False):
    """A live pairing for the install; skip when this run already paired.

    Portal pairs internally when the UDID is missing, so the pair stage would
    ask for a second PIN without this check.
    """
    state = load_state()
    try:
        age = time.time() - float(state.get("paired_at") or 0)
    except (TypeError, ValueError):                          # noqa: BLE001
        age = float("inf")
    record = os.path.join(STATE_DIR, "PairingFile_RemoteRP.plist")
    if state.get("udid") and os.path.isfile(record) and age < PAIRING_FRESH_SECS:
        print("  UDID      %s (paired %d min ago, reusing)" % (state["udid"], int(age // 60)))
        return 0
    if loopback:
        pair = os.path.join(_HERE, "pair_install.py")
        return subprocess.call([sys.executable, "-u", pair, "--loopback",
                                "--pair-only", "--keep-awake"])
    return cmd_udid([])


def _loopback_port():
    """RPPairing port behind LocalDevVPN, or 0. Same probe as pair --loopback."""
    import asyncio as _asyncio

    async def _open(port):
        try:
            _reader, writer = await _asyncio.wait_for(
                _asyncio.open_connection("10.7.0.1", port), 1.0)
            try:
                writer.close()
            except Exception:                               # noqa: BLE001
                pass
            return port
        except Exception:                                   # noqa: BLE001
            return None

    async def _scan():
        if await _open(49152):
            return 49152
        for chunk in range(49152, 49152 + 64, 16):
            found = await _asyncio.gather(*[_open(port) for port in range(chunk, chunk + 16)])
            hit = [port for port in found if port]
            if hit:
                return hit[0]
        return 0

    try:
        return _asyncio.run(_scan())
    except Exception:                                       # noqa: BLE001
        return 0


def argv_get(argv, flag):
    if flag in argv:
        position = argv.index(flag) + 1
        if position < len(argv):
            return argv[position]
    return ""


# Apple only accepts a sign-in that claims the platform the anisette data was made
# on, and Mac anisette is the kind that still signs in. These two report a Mac and
# come first; the rest of SideStore's curated list follows, HTTPS only.
TRUSTED_ANISETTE = (
    "https://mac-ani.jkcoxson.com",
    "https://ani.jkcoxson.com",
)


def _anisette_order(preferred):
    """The curated list, HTTPS only, with the Mac servers that work today first.

    All of these are official entries in SideStore's list and the software behind
    them is open source (omnisette-server, anisette-v3-server), so any https://
    entry is acceptable. Plain http:// entries are dropped: anisette headers have
    no business travelling in clear text.
    """
    order = []
    for url in list(preferred) + list(TRUSTED_ANISETTE) + signin.anisette_candidates(""):
        url = (url or "").rstrip("/")
        if not url.startswith("https://") or url in order:
            continue
        order.append(url)
    return order[:6]


def cmd_login(argv):
    """Apple sign-in."""
    preferred = argv_get(argv, "--server")
    use_clipboard = "--use-clipboard" in argv
    positional = [item for item in argv if not item.startswith("-") and item != preferred]
    given = bool(positional)
    email = positional[0] if given else ""
    if not email:
        # The address belongs on the sign-in screen, not on whatever screen was
        # showing when `login` started.
        _stage("Apple sign-in")
        email = _ask("  Apple ID: ").strip()
        if not email:
            print("no Apple ID")
            return 2
    reused = _reused_session(email)
    if reused is not None:
        update_state(email=email)
        _result("LOGIN", "ok  (saved session still works: no password, no 2FA)")
        return 0
    account = _sign_in(email, preferred, use_clipboard, staged=not given)
    update_state(email=email)
    name = ""
    try:
        name = (account.spd or {}).get("fn", "") if getattr(account, "spd", None) else ""
    except Exception:                                         # noqa: BLE001
        name = ""
    _result("LOGIN", "ok%s" % (("  " + name) if name else ""))
    return 0


def cmd_portal(argv):
    """Register the UDID, issue a certificate, download the profile."""
    state = load_state()
    email = state.get("email") or ""
    if not email:
        print("! no Apple ID: run login first")
        return 2

    variant = state.get("variant") or ""
    bundle_id = state.get("bundle_id") or ""
    if "--bundle-id" in argv:
        position = argv.index("--bundle-id") + 1
        if position >= len(argv):
            print("--bundle-id needs a value")
            return 2
        bundle_id = argv[position]
    if not bundle_id:
        variants = load_variants()
        if variants:
            _stage("Variant")
            for index, item in enumerate(variants, 1):
                print("  %d  %s" % (index, item["name"]))
            choice = _ask("  choose 1-%d: " % len(variants), "1")
            if choice.isdigit() and 1 <= int(choice) <= len(variants):
                variant = variants[int(choice) - 1]["id"]
                bundle_id = variants[int(choice) - 1]["bundle_id"]
    if not bundle_id:
        print("no bundle id")
        return 2

    udid = ""
    if "--udid" in argv:
        position = argv.index("--udid") + 1
        if position >= len(argv):
            print("--udid needs a value")
            return 2
        udid = normalise_udid(argv[position])
        if not udid:
            print("! that is not a UDID")
            return 2
    if not udid:
        udid = _ensure_udid(loopback=False)
    if not udid:
        return 1

    session = _login_session(email)
    result = _portal(session, email, udid, bundle_id, "BariSign device",
                     app_display_name(variant_id=variant, bundle_id=bundle_id))
    update_state(email=email, udid=udid, variant=variant or state.get("variant", ""),
                 bundle_id=result["bundle_id"], team_id=result["team_id"],
                 profile=result["profile"], key=result["key"], cert=result["cert"])
    _result("PORTAL", "ok")
    return 0


def _share_file(path):
    """Open a-Shell's preview so the share sheet can AirDrop the file."""
    print("  sharing   %s" % _display_path(path))
    marker = os.environ.get("TERM_PROGRAM", "").lower()
    a_shell = (sys.platform.startswith(("ios", "darwin"))
               or "a-shell" in marker or "ashell" in marker)
    if a_shell and sys.stdin.isatty():
        os.system("view %s" % shlex.quote(path))
    else:
        print("  path      %s" % path)


def _display_path(path):
    """The path as the Files app shows it, not the long container path."""
    docs = os.path.join(os.path.expanduser("~"), "Documents")
    full = os.path.abspath(path)
    if full == docs or full.startswith(docs + os.sep):
        return "Device/a-Shell/" + os.path.relpath(full, docs).replace(os.sep, "/")
    return path




_SIGN_STEPS = {"read": (1, 5, "ipa"), "open": (2, 5, "unpack"),
               "prepare": (2, 5, "prepare"), "sign": (3, 5, "sign"),
               "check": (4, 5, "verify"), "write": (4, 5, "package"),
               "zip": (5, 5, "zip"), "done": (5, 5, "done")}


def _sign_progress(label):
    index, total, text = _SIGN_STEPS.get(label, (3, 5, label))
    _step(index, total, text)


def _choose_variant(state, variants):
    """The one-line menu; remembers the choice in state."""
    while True:
        _stage("Variant")
        for index, item in enumerate(variants, 1):
            print("  %d  %s" % (index, item["name"]))
        print("  %d  custom IPA (first drop the .ipa into Custom IPAs)" % (len(variants) + 1))
        choice = _ask("  choose 1-%d: " % (len(variants) + 1), "1")
        if choice == str(len(variants) + 1):
            chosen = _choose_custom_ipa(state)
            if chosen is not None:
                return chosen
            continue
        if not (choice.isdigit() and 1 <= int(choice) <= len(variants)):
            choice = "1"
        chosen = variants[int(choice) - 1]
        update_state(variant=chosen["id"], bundle_id=chosen["bundle_id"])
        print("  %s" % chosen["name"])
        return chosen


def _find_signer_ipas(limit=40):
    """IPAs the user dropped into ~/Documents/Custom IPAs, newest first.

    That folder (Files > On My iPhone/iPad > a-Shell > Custom IPAs) is the
    only place custom IPAs are picked up from; BariSign's own signed and
    downloaded IPAs live in the ipa/ folder inside BariSign instead.
    """
    try:
        os.makedirs(CUSTOM_IPA_DIR, exist_ok=True)
    except OSError:
        pass
    found = []
    for dirpath, dirnames, filenames in os.walk(CUSTOM_IPA_DIR):
        if os.path.relpath(dirpath, CUSTOM_IPA_DIR).count(os.sep) > 1:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            if not name.lower().endswith(".ipa"):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) < 1024 * 1024 or not os.path.isfile(full):
                    continue
            except OSError:
                continue
            if full not in found:
                found.append(full)
        if len(found) >= limit:
            break
    try:
        found.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    except OSError:
        pass
    return found[:limit]


def _resolve_ipa_path(typed):
    """Turn what the user typed into an IPA path, or ''.

    Accepts absolute paths, ~/ paths and bare file names (looked up in the
    same places the picker scans).
    """
    if not typed:
        return ""
    candidates = [os.path.abspath(os.path.expanduser(typed)),
                  os.path.join(CUSTOM_IPA_DIR, typed),
                  os.path.join(CUSTOM_IPA_DIR, os.path.basename(typed)),
                  os.path.join(os.path.expanduser("~"), "Documents", typed)]
    for candidate in candidates:
        if os.path.isfile(candidate) and candidate.lower().endswith(".ipa"):
            return candidate
    for found in _find_signer_ipas():
        if os.path.basename(found) == os.path.basename(typed):
            return found
    return ""


def _choose_custom_ipa(state):
    """Let the user pick an IPA already on the signer.

    A numbered list when IPAs are found; when the folder is empty, an info
    screen waits for the drop and rescans. A distinct bundle id needs its own
    App ID, and a free Apple ID has 10 App ID slots.
    """
    while True:
        found = _find_signer_ipas()
        _stage("Custom IPA")
        print("  put the .ipa in Files > On My iPhone/iPad >")
        print("  a-Shell > Custom IPAs, then pick it below.")
        print("  folder: %s" % _display_path(CUSTOM_IPA_DIR))
        print()
        if not found:
            print("  the folder is empty right now.")
            print("  drop the .ipa in, come back, press Enter to rescan.")
            typed = _ask("  Enter = rescan, back = go back: ").strip().lower()
            if typed in ("back", "b", "q"):
                return None
            continue
        print("  IPAs in Custom IPAs (newest first):")
        for index, path in enumerate(found, 1):
            try:
                size = os.path.getsize(path) / 1048576.0
            except OSError:
                size = 0
            print("  %d  %s  (%.1f MB)" % (index, os.path.basename(path), size))
        print("  or paste a path below (a new drop needs a rescan first).")
        picked = None
        for _attempt in range(3):
            typed = _ask("  number or path (empty = back): ").strip()
            if not typed:
                return None
            if typed.isdigit() and found and 1 <= int(typed) <= len(found):
                path = found[int(typed) - 1]
            else:
                path = _resolve_ipa_path(typed)
            if not path:
                print("  ! not found, try again")
                continue
            bundle_id = _ipa_bundle_id(path)
            if not bundle_id:
                print("  ! not an IPA (no Payload/*.app/Info.plist)")
                continue
            picked = (path, bundle_id)
            break
        if picked is None:
            # Three misses: a file may have landed meanwhile, so rescan
            # instead of dropping back to the menu.
            continue
        path, bundle_id = picked
        update_state(variant="custom", bundle_id=bundle_id, ipa=path)
        print("  bundle   %s" % bundle_id)
        return {"id": "custom", "name": os.path.basename(path),
                "bundle_id": bundle_id, "custom_ipa": path}


def _ipa_bundle_id(path):
    """CFBundleIdentifier of the top-level app inside an IPA, or ''."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist()
                     if name.startswith("Payload/") and name.endswith(".app/Info.plist")
                     and name.count("/") == 2]
            if not names:
                return ""
            info = plistlib.loads(archive.read(names[0]))
            return info.get("CFBundleIdentifier") or ""
    except Exception:                                           # noqa: BLE001
        return ""


def _obtain_ipa(state, argv):
    """Return (path, info): --ipa, else the chosen variant's current release."""
    typed = argv_get(argv, "--ipa")
    if typed:
        path = os.path.abspath(os.path.expanduser(typed))
        if not os.path.isfile(path):
            print("  ! not found: %s" % path)
            return "", {}
        bundle_id = _ipa_bundle_id(path)
        if not bundle_id:
            print("  ! not an IPA (no Payload/*.app/Info.plist): %s" % path)
            return "", {}
        return path, {"version": os.path.basename(path), "bundle_id": bundle_id}

    variants = load_variants()
    variant = download.variant_by_id(variants, state.get("variant") or "")
    if variant is None and (state.get("variant") or "") == "custom":
        path = state.get("ipa") or ""
        if path and os.path.isfile(path):
            bundle_id = _ipa_bundle_id(path) or state.get("bundle_id") or ""
            if bundle_id:
                return path, {"version": os.path.basename(path), "bundle_id": bundle_id}
        print("  ! the custom IPA is gone: %s" % (path or "(no file saved)"))
        return "", {}
    if variant is None:
        if not variants:
            print("  ! variants.json is missing or empty")
            return "", {}
        variant = _choose_variant(state, variants)
        state = load_state()

    folder = UNSIGNED_DIR
    try:
        info = download.resolve(variant)
    except download.DownloadError as exc:
        # Offline fallback: the current unsigned/ folder, then the old
        # program-folder location from before the split.
        saved = ""
        for candidate in (os.path.join(folder, (variant.get("id") or "barisign") + ".ipa"),
                          os.path.join(os.path.dirname(STATE_DIR),
                                       (variant.get("id") or "barisign") + ".ipa")):
            if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
                saved = candidate
                break
        if saved:
            _result("IPA", "%s (no GitHub; using the saved file)"
                    % os.path.basename(saved))
            return saved, {"version": "saved file"}
        _line_clear()
        print()
        print("! %s" % exc)
        return "", {}

    size_mb = (info["size"] or 0) / 1048576.0
    # The version string is the proof this run really asked GitHub: stable
    # shows the tag, nightly shows the asset date (its published_at is stale).
    print(("  %s (%.1f MB)" % (info.get("version") or variant["name"], size_mb))[:_columns() - 1])
    last = [-5]

    def moved(received, total):
        percent = int(received * 100 / total) if total else 0
        if percent >= last[0] + 5 or percent == 100:
            last[0] = percent
            _step(1, 1, "downloading %d%%" % percent)

    try:
        info = download.ensure(variant, folder, moved)
    except download.DownloadError as exc:
        _line_clear()
        print()
        print("! %s" % exc)
        return "", {}
    _line_clear()
    # Reuse is only allowed when size AND GitHub's SHA-256 match, so a
    # cached file can never hide a newer release: resolve() ran above on
    # every run and the mismatch forces a fresh download.
    if info.get("reused"):
        print("  %s (cached, still current)" % (info.get("version") or variant["name"]))
    update_state(variant=variant["id"], asset_version=info["version"])
    update_state(ipa=info["path"])
    return info["path"], info


def _sign_now(ipa, saved, argv, hint=True, make_zip=None):
    """Run the signer, then print the two closing lines."""
    if make_zip is None:
        make_zip = "--no-zip" not in argv
    out = argv_get(argv, "--out")
    if not out:
        # Signed outputs live in ipa/signed/ inside BariSign: originals stay
        # in ipa/unsigned/, custom inputs stay in ~/Documents/Custom IPAs.
        os.makedirs(SIGNED_DIR, exist_ok=True)
        base = os.path.basename(ipa)
        stem = base[:-4] if base.lower().endswith(".ipa") else base
        out = os.path.join(SIGNED_DIR, stem + "-signed.ipa")
    try:
        result = signer.sign_ipa(ipa, saved["profile"], saved["key"], saved["cert"],
                                 output_ipa=out,
                                 udid=saved.get("udid") or None,
                                 progress=_sign_progress,
                                 make_zip=make_zip,
                                 drop_extensions="--no-extensions" in argv)
    except signer.SigningError as exc:
        _line_clear()
        print()
        print("! %s" % exc)
        return None
    update_state(ipa=ipa, signed_ipa=result["ipa"], zip=result["zip"])
    _result("SIGN", "ok  %s" % os.path.basename(result["ipa"]))
    if result["zip"]:
        print("  zip   %s" % _display_path(result["zip"]))
    if hint:
        print("  next  sh barisign pair  (install on the target over Wi-Fi)")
    return result


def cmd_sign(argv):
    """Download the chosen variant (unless --ipa) and sign it."""
    _stage("Sign")
    saved = signer.find_saved_paths(STATE_DIR)
    missing = [label for label, path in (("key", saved["key"]),
                                         ("cert", saved["cert"]),
                                         ("profile", saved["profile"])) if not path]
    if missing:
        print("  ! no %s: run 'sh barisign portal' first" % ", ".join(missing))
        return 2

    ipa, info = _obtain_ipa(load_state(), argv)
    if ipa and info.get("bundle_id"):
        if _adopt_custom_bundle_id(info["bundle_id"]) is None:
            return 1
    if not ipa:
        return 1
    if _sign_now(ipa, saved, argv) is None:
        return 1
    return 0


def cmd_shell(argv):
    """Single-device full install: check -> Apple ID -> variant -> download ->
    portal -> pair -> sign -> install. No flags: loopback and keep-awake are
    always on, because that is what this command is.
    """
    if "--help" in argv or "-h" in argv or "help" in argv:
        print("BariSign %s" % VERSION)
        print()
        print("  sh barisign shell   terminal run without the web page")
        print("  needs LocalDevVPN connected on this device; volume audible")
        return 0
    pair = os.path.join(_HERE, "pair_install.py")
    state = load_state()
    print("BariSign %s" % VERSION)
    if poc_login._selftest(quiet=True) != 0:
        print("check  fail: run 'sh barisign check' for the details")
        return 1
    print("check  ok")

    email = state.get("email") or ""
    if not email:
        _stage("Apple sign-in")
        email = _ask("  Apple ID: ").strip()
        if not email:
            print("no Apple ID")
            return 2
    _stage("Requirements")
    print("  this device needs: Developer Mode ON, LocalDevVPN connected,")
    print("  volume audible (the app speaks while you pair).")
    print("  later: Settings > Developer > Paired Macs, enter the PIN shown here.")
    while True:
        if _loopback_port():
            print("  loopback     LocalDevVPN answers")
            break
        print("  ! LocalDevVPN is not answering on this device")
        print("    connect it, then continue.")
        _ask("  press Enter when connected (Ctrl-C to stop): ")

    session = _login_session(email, staged=not state.get("email"))
    update_state(email=email)
    state = load_state()

    variants = load_variants()
    if variants:
        _choose_variant(state, variants)
        state = load_state()

    _stage("Download")
    ipa, _info = _obtain_ipa(state, [])
    if not ipa:
        return 1
    if _info.get("bundle_id"):
        if _adopt_custom_bundle_id(_info["bundle_id"]) is None:
            return 1
        state = load_state()

    # Portal registers the device, so it needs the UDID first: the loopback
    # pairing runs here, inside the portal stage.
    udid = _ensure_udid(loopback=True)
    if not udid:
        print("  pairing did not return a UDID")
        print("  turn on Developer Mode, connect LocalDevVPN, run again")
        return 1
    state = load_state()

    result = _portal(session, email, udid, state.get("bundle_id", ""),
                     "BariSign device",
                     app_display_name(variant_id=state.get("variant", ""),
                                      bundle_id=state.get("bundle_id", "")))
    update_state(bundle_id=result["bundle_id"], team_id=result["team_id"],
                 profile=result["profile"], key=result["key"], cert=result["cert"])
    _result("PORTAL", "ok")

    # The install needs a live pairing. Skipped when portal just paired,
    # so one run asks for one PIN.
    _stage("Pairing")
    print("  same device: Settings > Developer > Paired Macs")
    print("  this app keeps speaking while you are over there;")
    print("  enter the printed PIN on the Paired Macs screen.")
    state = load_state()
    if _ensure_pairing(loopback=True) != 0:
        return 1
    state = load_state()

    _stage("Sign")
    saved = signer.find_saved_paths(STATE_DIR)
    result = _sign_now(ipa, saved, [], hint=False, make_zip=False)
    if result is None:
        return 1
    if _yes("  install on this device now?", True):
        command = [sys.executable, "-u", pair, "--loopback", "--keep-awake",
                   "--ipa", result["ipa"]]
        paired = load_state()
        if paired.get("paired") and paired.get("udid"):
            command += ["--udid", paired["udid"]]
        return subprocess.call(command)
    return 0


def cmd_pair(argv):
    """Pair the target and install the signed IPA (pair_install.py)."""
    pair = os.path.join(_HERE, "pair_install.py")
    return subprocess.call([sys.executable, "-u", pair] + list(argv))


COMMANDS = {
    "pair": cmd_pair,
    "version": cmd_version,
    "check": cmd_check,
    "status": cmd_status,
    "forget": cmd_forget,
    "reset": cmd_reset,
    "udid": cmd_udid,
    "login": cmd_login,
    "portal": cmd_portal,
    "sign": cmd_sign,
    "shell": cmd_shell,
}


_OPTIONS = {
    "pair": (
        ("--pair-only", "pair, print the UDID and write the pairing file"),
        ("--ipa FILE", "install this signed IPA"),
        ("--udid UDID", "reuse an existing pairing for this UDID"),
        ("--import FILE", "use a pairing file from another host (Mac/SideInstaller)"),
        ("--check", "python, cryptography and engine import only"),
        ("--setup", "verify the pure engine (nothing is downloaded)"),
        ("--timeout N", "give up if the target does not pair"),
        ("--host IP", "use this target address; the pairing port is scanned"),
        ("--loopback", "EXPERIMENTAL same-device install via LocalDevVPN"),
        ("--loopback-port P", "loopback port (default: probe 49152 + range)"),
        ("--keep-awake", "EXPERIMENTAL speech loop to hold the process"),
        ("--devmode CMD", "Developer Mode: status, show or on"),
        ("--no-devmode", "skip the Developer Mode check"),
        ("--raw-mdns", "force raw advertisement (automatic on a-Shell)"),
        ("--target-ip IP", "also send unicast mDNS to the target"),
        ("--repair", "new host identity; the target asks to pair again"),
        ("--export [FILE]", "copy the pairing file out (default: ~/Documents)"),
        ("--debug", "print the full traceback on failure"),
    ),
    "login": (
        ("--use-clipboard", "take the password from the clipboard, no typing"),
        ("--server URL", "pin an anisette server"),
    ),
    "portal": (
        ("--udid UDID", "register another target device too"),
    ),
    "sign": (
        ("--ipa FILE", "sign this file instead of downloading"),
        ("--out FILE", "write the signed IPA here"),
        ("--no-zip", "do not package the .zip copy (install uses the .ipa)"),
        ("--no-extensions", "drop PlugIns (an app extension needs its own App ID)"),
    ),
    "udid": (
    ),
}


def _usage():
    print("BariSign %s" % VERSION)
    print()
    print("  sh barisign           web UI: the whole install on this iPhone")
    print("  sh barisign udid      pair this iPhone, save its UDID")
    print("  sh barisign login     Apple sign-in")
    print("  sh barisign portal    UDID + certificate + profile")
    print("  sh barisign sign      download, sign and zip the chosen variant")
    print("  sh barisign pair      pair over loopback and install the newest IPA")
    print("  sh barisign status    what is saved")
    print("  sh barisign check     diagnostics only")
    print("  sh barisign version   which copy is running")
    print("  sh barisign update    update everything in place")
    print("  sh barisign forget    clear the saved state")
    print("  sh barisign reset      remove saved state, IPAs and zips")
    print()
    print("  options: sh barisign <command> help")


def _options(command):
    print("BariSign %s" % VERSION)
    print()
    print("  sh barisign %s" % command)
    for flag, text in _OPTIONS[command]:
        print()
        print("    %s" % flag)
        print("        %s" % text)


def main(argv):
    if not argv:
        import webui
        return webui.run()
    if argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0
    if len(argv) >= 2 and argv[1] == "help" and argv[0] in _OPTIONS:
        _options(argv[0])
        return 0

    command = argv[0]
    handler = COMMANDS.get(command)
    if handler is None:
        print("unknown command: %s" % command)
        _usage()
        return 2


    return handler(argv[1:])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Fail as exc:
        print()
        print("! %s" % exc)
        sys.exit(1)
    except BrokenPipeError:
        # `barisign.py ... | head` closes the pipe early; that is not an error.
        os._exit(0)
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except Exception:                                         # noqa: BLE001
        print()
        print("UNEXPECTED ERROR:")
        traceback.print_exc()
        sys.exit(4)
