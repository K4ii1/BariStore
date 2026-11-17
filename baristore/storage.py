#!/usr/bin/env python3
# =============================================================================
#  BariStore — Persistent State, Migration, and File Paths (MIT)
# =============================================================================

import json
import os
import plistlib
import re
import shutil
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATE_DIR = os.environ.get("BARISTORE_STATE_DIR") or os.path.join(ROOT, "state")
STATE_FILE = os.path.join(STATE_DIR, "baristore.json")
INSTALLED_FILE = os.path.join(STATE_DIR, "installed_apps.json")
SOURCES_CACHE_FILE = os.path.join(STATE_DIR, "sources_cache.json")
ANISETTE_STATE_FILE = os.path.join(STATE_DIR, "anisette.json")

RECORD_PATH = os.path.join(STATE_DIR, "PairingFile_RemoteRP.plist")
ALT_RECORD_PLIST = os.path.join(STATE_DIR, "ALTPairingFile.plist")
ALT_RECORD_PAIRING = os.path.join(STATE_DIR, "ALTPairingFile.mobiledevicepairing")
IDENTITY_PATH = os.path.join(STATE_DIR, "pairing_host.plist")

IPA_DIR = os.path.join(ROOT, "ipa")
UNSIGNED_DIR = os.path.join(IPA_DIR, "unsigned")
SIGNED_DIR = os.path.join(IPA_DIR, "signed")
UPLOAD_DIR = os.path.join(IPA_DIR, "uploads")
CUSTOM_IPA_DIR = os.path.join(os.path.expanduser("~"), "Documents", "Custom IPAs")
SOURCES_CONFIG_FILE = os.path.join(ROOT, "sources.json")

_LOCK = threading.RLock()


def ensure_dirs():
    for path in (STATE_DIR, IPA_DIR, UNSIGNED_DIR, SIGNED_DIR, UPLOAD_DIR):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass
    try:
        os.makedirs(CUSTOM_IPA_DIR, exist_ok=True)
    except OSError:
        pass


ensure_dirs()


def normalise_udid(value):
    cleaned = re.sub(r"[\s\-]", "", str(value or "")).lower()
    if len(cleaned) == 40 and re.fullmatch(r"[0-9a-f]{40}", cleaned):
        return cleaned
    if len(cleaned) == 24 and re.fullmatch(r"[0-9a-f]{24}", cleaned):
        return cleaned[:8] + "-" + cleaned[8:]
    return ""


def load_state():
    with _LOCK:
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            return state if isinstance(state, dict) else {}
        except Exception:
            return {}


def save_state(state):
    with _LOCK:
        ensure_dirs()
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
        os.replace(tmp, STATE_FILE)
        return state


def update_state(**values):
    with _LOCK:
        state = load_state()
        state.update(values)
        return save_state(state)


def has_pairing_record():
    if not os.path.isfile(RECORD_PATH):
        return False
    try:
        with open(RECORD_PATH, "rb") as handle:
            rec = plistlib.load(handle)
        return bool(rec.get("private_key") and rec.get("public_key") and (rec.get("identifier") or rec.get("host_identifier")))
    except Exception:
        return False


def save_pairing_record(record_dict):
    """Save the pairing record in all three standard filenames."""
    with _LOCK:
        ensure_dirs()
        data = record_dict.as_dict() if hasattr(record_dict, "as_dict") else dict(record_dict)
        raw = plistlib.dumps(data, fmt=plistlib.FMT_XML)
        for path in (RECORD_PATH, ALT_RECORD_PLIST, ALT_RECORD_PAIRING):
            tmp = path + ".tmp"
            with open(tmp, "wb") as handle:
                handle.write(raw)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, path)
        udid = normalise_udid(data.get("peer_udid") or "")
        update_state(
            paired=True,
            udid=udid or load_state().get("udid", ""),
            peer_name=data.get("peer_name") or load_state().get("peer_name", ""),
            peer_model=data.get("peer_model") or load_state().get("peer_model", ""),
            paired_at=int(time.time()),
            record=RECORD_PATH,
        )
        return RECORD_PATH


def export_pairing_bytes():
    """Return the normalized RPPairing XML plist bytes for apps (SideStore/AltStore/StikDebug)."""
    if not os.path.isfile(RECORD_PATH):
        raise FileNotFoundError("No pairing file found. Pair your device first.")
    with open(RECORD_PATH, "rb") as handle:
        record = plistlib.loads(handle.read())
    keys = ("public_key", "private_key", "identifier", "alt_irk")
    filtered = {}
    for k in keys:
        val = record.get(k)
        if not val and k == "identifier":
            val = record.get("host_identifier")
        if not val and k == "alt_irk":
            val = record.get("host_alt_irk")
        if k == "private_key" and isinstance(val, (bytes, bytearray)) and len(val) == 64:
            val = bytes(val)[:32]
        if val:
            filtered[k] = val
    return plistlib.dumps(filtered, fmt=plistlib.FMT_XML)


def load_installed_apps():
    with _LOCK:
        try:
            with open(INSTALLED_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, list) else []
        except Exception:
            return []


def save_installed_apps(apps):
    with _LOCK:
        ensure_dirs()
        tmp = INSTALLED_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(apps, handle, indent=2)
        os.replace(tmp, INSTALLED_FILE)
        return apps


def record_installed_app(app_entry):
    """Add or update an installed app record in installed_apps.json."""
    with _LOCK:
        apps = load_installed_apps()
        bundle_id = app_entry.get("bundle_id") or ""
        original_bundle_id = app_entry.get("original_bundle_id") or bundle_id
        now = int(time.time())
        app_entry.setdefault("installed_at", now)
        app_entry["refreshed_at"] = now
        app_entry.setdefault("expires_at", now + 7 * 86400)
        updated = False
        for idx, existing in enumerate(apps):
            if (existing.get("bundle_id") == bundle_id and bundle_id) or (
                existing.get("original_bundle_id") == original_bundle_id and original_bundle_id
            ):
                merged = dict(existing)
                merged.update(app_entry)
                apps[idx] = merged
                updated = True
                break
        if not updated:
            apps.insert(0, app_entry)
        return save_installed_apps(apps)


def remove_installed_app(bundle_id):
    with _LOCK:
        apps = load_installed_apps()
        kept = [
            a for a in apps
            if a.get("bundle_id") != bundle_id and a.get("original_bundle_id") != bundle_id
        ]
        return save_installed_apps(kept)


def clear_cache():
    """Remove cached unsigned/signed/uploaded IPAs and source cache, keeping account & pairing."""
    removed = 0
    for folder in (UNSIGNED_DIR, SIGNED_DIR, UPLOAD_DIR):
        if os.path.isdir(folder):
            for name in os.listdir(folder):
                path = os.path.join(folder, name)
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                        removed += 1
                except OSError:
                    pass
    if os.path.isfile(SOURCES_CACHE_FILE):
        try:
            os.remove(SOURCES_CACHE_FILE)
            removed += 1
        except OSError:
            pass
    return removed


def factory_reset():
    """Wipe all state, cached IPAs, and settings."""
    with _LOCK:
        clear_cache()
        if os.path.isdir(STATE_DIR):
            shutil.rmtree(STATE_DIR, ignore_errors=True)
        ensure_dirs()
