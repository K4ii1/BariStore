#!/usr/bin/env python3
# =============================================================================
#  BariSign — pair the target and install the signed IPA (MIT)
#
#  Runs on the SIGNER inside a-Shell.  No pip, no qh3, no sslpsk, no native
#  wheel: every protocol piece is implemented in pure Python on top of the
#  cryptography 3.4.8 that a-Shell ships.
#
#      barisign pair                 pair (if needed) and install
#      barisign pair --pair-only     pair, save the UDID, stop
#      barisign pair --check         verify the pure engine imports
#      barisign pair --ipa FILE      install a specific signed IPA
#      barisign pair --loopback      EXPERIMENTAL: same-device install
#                                        through LocalDevVPN (10.7.0.1)
#
#  The target only uses Settings > Developer > Paired Macs and then opens the
#  app.  UNTESTED ON A DEVICE: the tunnel/install path is Linux-tested only.
# =============================================================================

import asyncio
import glob
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATE_DIR = os.environ.get("BARISIGN_STATE_DIR") or os.path.join(ROOT, "state")
RECORD_PATH = os.path.join(STATE_DIR, "PairingFile_RemoteRP.plist")
IDENTITY_PATH = os.path.join(STATE_DIR, "pairing_host.plist")

for _path in (HERE, ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import device_services
from device_services import DeviceServiceError
import devmode
import mdns
import pairing
import raw_mdns
import remote_xpc
import rpp_tunnel
import tcp6


def _say(text=""):
    print(text, flush=True)


def _ask(prompt, default=""):
    entered = (_read_line(prompt) or "").strip()
    return entered or (default or "")


CLEAR = "\033[2J\033[1;1H"


def _clear_screen():
    """Same ordering as the guided flow: scroll the old page away first, and
    only then drop the scrollback — otherwise a-Shell shows a blank page and
    the view ends up somewhere the user has to scroll back to."""
    try:
        import shutil
        rows = max(1, shutil.get_terminal_size((40, 24)).lines)
    except Exception:                                           # noqa: BLE001
        rows = 24
    sys.stdout.write("\033[0m" + "\n" * (2 * rows) + "\033[3J" + "\n" * rows + CLEAR)
    sys.stdout.flush()


def _read_line(prompt):
    """One line, read byte by byte on a TTY.

    Plain input() misbehaves on a-Shell once terminal modes were touched; our
    own echo works even then. Non-TTY runs use input() so pipes keep working.
    """
    if sys.stdin.isatty():
        import poc_login
        return poc_login._masked_line(prompt, mask=False)
    try:
        return input(prompt)
    except EOFError:
        return ""


def _stage(title, lines=()):
    """One clean screen per stage, like the guided flow."""
    _clear_screen()
    print("BariSign")
    print()
    print("== %s ==" % title.upper())
    for line in lines:
        print("  %s" % line)
    print()


# --------------------------------------------------------------------------
# Experimental: same-device loopback + background keep-alive
# --------------------------------------------------------------------------
#
# SideInstaller/StikPair/SideStore do on-device pairing+install from a NATIVE
# app: silent audio holds the process while the user is in Settings, and a
# LocalDevVPN loopback (10.7.0.1) reaches the phone's own lockdownd. From a
# Python guest inside a-Shell only two halves are reachable:
#   * outbound TCP to the loopback address needs no entitlement (a-Shell has
#     network.client), so the tunnel/install code runs unchanged against it;
#   * holding the process while backgrounded has exactly one tool: audible
#     speech through `say` (no silent-audio API is exposed to Python).
# Both halves are EXPERIMENTAL and UNVERIFIED on a device.

LOOPBACK_HOST = "10.7.0.1"

_KEEP_AWAKE_TEXT = (
    "BariSign is pairing. Please stay in Settings and enter the code. "
    "BariSign is pairing. Please stay in Settings and enter the code."
)


def keep_awake_start():
    """Speak in a loop so iOS keeps the process alive (best effort).

    Returns a stop function. When `say` is missing (Linux, CI) it is a no-op
    that reports so. UNVERIFIED: whether speech holds us through a Settings
    switch on a real device.
    """
    if shutil.which("say") is None:
        _say("  keep-awake   no `say` here; continuing without it")
        return lambda: None
    _say("  keep-awake   speaking until pairing ends (lower the volume)")
    stop = threading.Event()

    def _loop():
        while not stop.is_set():
            try:
                proc = subprocess.Popen(["say", "-r", "90", _KEEP_AWAKE_TEXT])
            except Exception:                                   # noqa: BLE001
                return
            while proc.poll() is None and not stop.is_set():
                stop.wait(0.5)
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:                                   # noqa: BLE001
                pass

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

    def _stop():
        stop.set()
        thread.join(timeout=5)

    return _stop


async def loopback_probe(host, explicit_port=0):
    """Find the RPPairing port behind a LocalDevVPN loopback address.

    Explicit --loopback-port wins; otherwise 49152, otherwise a short scan of
    the usual range. Raises a plain error naming LocalDevVPN when shut.
    UNVERIFIED: which port (if any) answers on a real device.
    """
    if explicit_port:
        if await _tcp_open(host, explicit_port, timeout=2.0):
            return explicit_port
        raise RuntimeError(
            "nothing answered on %s:%d "
            "(is LocalDevVPN installed and connected?)" % (host, explicit_port))
    if await _tcp_open(host, 49152, timeout=2.0):
        return 49152
    found = await scan_ports(host, start=49152, count=64, timeout=2.0, batch=16)
    if found:
        return found[0]
    raise RuntimeError(
        "nothing answered on %s "
        "(is LocalDevVPN installed and connected?)" % host)


def _udid_ok(value):
    cleaned = re.sub(r"[\s\-]", "", (value or "")).lower()
    return bool(re.fullmatch(r"[0-9a-f]{40}", cleaned) or re.fullmatch(r"[0-9a-f]{24}", cleaned))


def normalise_udid(value):
    cleaned = re.sub(r"[\s\-]", "", (value or "")).lower()
    if len(cleaned) == 40 and re.fullmatch(r"[0-9a-f]{40}", cleaned):
        return cleaned
    if len(cleaned) == 24 and re.fullmatch(r"[0-9a-f]{24}", cleaned):
        return cleaned[:8] + "-" + cleaned[8:]
    return ""


def load_state():
    try:
        with open(os.path.join(STATE_DIR, "barisign.json")) as handle:
            return json.load(handle)
    except Exception:                                           # noqa: BLE001
        return {}


def save_state(**values):
    os.makedirs(STATE_DIR, exist_ok=True)
    state = load_state()
    state.update(values)
    with open(os.path.join(STATE_DIR, "barisign.json"), "w") as handle:
        json.dump(state, handle, indent=2)
    return state


def display_path(path):
    """Short path as the Files app shows it, not the long container path."""
    docs = os.path.join(os.path.expanduser("~"), "Documents")
    full = os.path.abspath(path)
    if full == docs or full.startswith(docs + os.sep):
        return "Device/a-Shell/" + os.path.relpath(full, docs).replace(os.sep, "/")
    return path


REGISTRY_PATH = os.path.join(STATE_DIR, "paired_devices.json")
PAIRINGS_DIR = os.path.join(STATE_DIR, "pairings")


def _norm_id(value):
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def load_registry():
    try:
        with open(REGISTRY_PATH) as handle:
            entries = json.load(handle)
        if isinstance(entries, list):
            return [entry for entry in entries
                    if isinstance(entry, dict) and entry.get("file")
                    and os.path.isfile(entry["file"])]
    except Exception:                                           # noqa: BLE001
        pass
    return []


def save_registry(entries):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = REGISTRY_PATH + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(entries, handle, indent=2)
    os.replace(tmp, REGISTRY_PATH)


def registry_migrate():
    """Adopt the pre-menu single record file as the first registry entry."""
    entries = load_registry()
    if entries:
        return entries
    try:
        record = rpp_tunnel.load_record(RECORD_PATH)
    except Exception:                                           # noqa: BLE001
        return []
    udid = normalise_udid(record.get("peer_udid") or "")
    key = _norm_id(udid) or _norm_id(record.get("peer_identifier")) or "device"
    os.makedirs(PAIRINGS_DIR, exist_ok=True)
    path = os.path.join(PAIRINGS_DIR, key + ".plist")
    if not os.path.isfile(path):
        with open(path, "wb") as handle:
            handle.write(plistlib.dumps(record))
        os.chmod(path, 0o600)
    entry = {"udid": udid,
             "name": record.get("peer_name") or "target",
             "model": record.get("peer_model") or "",
             "identifier": record.get("peer_identifier") or "",
             "file": path,
             "peer_ip": load_state().get("peer_ip") or "",
             "last_used": 0}
    save_registry([entry])
    return [entry]


def registry_upsert(info, record_path, peer_ip):
    """Store/refresh the entry for a freshly paired device (newest first)."""
    entries = load_registry()
    udid = normalise_udid(info.get("udid", ""))
    key = _norm_id(udid) or _norm_id(info.get("identifier")) or "device"
    os.makedirs(PAIRINGS_DIR, exist_ok=True)
    path = os.path.join(PAIRINGS_DIR, key + ".plist")
    with open(record_path, "rb") as handle:
        data = handle.read()
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    entries = [entry for entry in entries
               if _norm_id(entry.get("udid")) != _norm_id(udid) or not udid]
    import time as _time
    entry = {"udid": udid,
             "name": info.get("name") or "target",
             "model": info.get("model") or "",
             "identifier": info.get("identifier") or "",
             "file": path,
             "peer_ip": peer_ip or "",
             "last_used": int(_time.time())}
    entries.insert(0, entry)
    save_registry(entries)
    return entries


def registry_activate(entry):
    """Make an entry's record the active one; return the loaded record."""
    with open(entry["file"], "rb") as handle:
        data = handle.read()
    for name in ("PairingFile_RemoteRP.plist", "ALTPairingFile.plist",
                 "ALTPairingFile.mobiledevicepairing"):
        path = os.path.join(STATE_DIR, name)
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    record = rpp_tunnel.load_record(RECORD_PATH)
    udid = normalise_udid(record.get("peer_udid") or entry.get("udid") or "")
    save_state(paired=True, udid=udid, peer_ip=entry.get("peer_ip") or "",
               peer_name=entry.get("name") or "", record=RECORD_PATH)
    return record, udid


def choose_device(entries):
    """Interactive device menu. Returns ('entry', entry), ('new', None)."""
    _stage("Pairing", ["previously paired devices:"])
    for index, entry in enumerate(entries, 1):
        label = entry.get("name") or "target"
        model = entry.get("model") or ""
        udid = entry.get("udid") or ""
        _say("  %d  %s%s  %s" % (index, label,
                                 (" (%s)" % model) if model else "", udid))
    _say("  %d  pair a new device" % (len(entries) + 1))
    _say("")
    choice = _ask("  choose 1-%d: " % (len(entries) + 1), "1")
    if choice == str(len(entries) + 1):
        return "new", None
    if choice.isdigit() and 1 <= int(choice) <= len(entries):
        return "entry", entries[int(choice) - 1]
    return "entry", entries[0]


def save_record(record):
    """Write the normalized pairing record for BariSign and for the apps."""
    os.makedirs(STATE_DIR, exist_ok=True)
    data = record.as_dict() if hasattr(record, "as_dict") else dict(record)
    raw = plistlib.dumps(data)
    for name in ("PairingFile_RemoteRP.plist", "ALTPairingFile.plist",
                 "ALTPairingFile.mobiledevicepairing"):
        path = os.path.join(STATE_DIR, name)
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            handle.write(raw)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    return os.path.join(STATE_DIR, "PairingFile_RemoteRP.plist")


def ipa_bundle_id(ipa):
    try:
        with zipfile.ZipFile(ipa) as archive:
            names = [name for name in archive.namelist()
                     if name.startswith("Payload/") and name.endswith(".app/Info.plist")
                     and name.count("/") == 2]
            if not names:
                return ""
            info = plistlib.loads(archive.read(names[0]))
            return info.get("CFBundleIdentifier") or ""
    except Exception:                                           # noqa: BLE001
        return ""


def find_ipa(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else ""
    candidates = []
    for pattern in (os.path.join(ROOT, "ipa", "signed", "*-signed.ipa"),
                    os.path.join(STATE_DIR, "*-signed.ipa"),
                    os.path.join(ROOT, "*-signed.ipa")):
        candidates.extend(glob.glob(pattern))
    candidates = [path for path in candidates if os.path.isfile(path)]
    return max(candidates, key=os.path.getmtime) if candidates else ""


# --------------------------------------------------------------------------
# Pairing
# --------------------------------------------------------------------------

def _ashell_limited():
    """True where DNS-SD registration is known to fail (a-Shell/iOS sandbox).

    Plain `pair` then goes straight to the raw advertiser instead of wasting
    a DNS-SD attempt that always returns -65555. `--raw-mdns` forces the same.
    """
    import sys as _sys
    return (os.environ.get("TERM_PROGRAM", "") == "a-Shell"
            or os.environ.get("BARISIGN_ASHELL") == "1"
            or _sys.platform == "ios")


def _debug_path():
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, "pair_debug.log")


def _debug_log(handle, text):
    try:
        handle.write(text + "\n")
        handle.flush()
    except Exception:                                           # noqa: BLE001
        pass


async def pair_target(timeout, identity, raw=False, target_ip=""):
    """Advertise BariSign, accept one device-initiated pairing."""
    result = asyncio.get_running_loop().create_future()
    debug_handle = open(_debug_path(), "w")
    # The target may dial twice (IPv4 + IPv6 Happy Eyeballs): run pair-setup
    # on the first connection only, or the two interleaved sessions poison
    # each other and the result. Retries connect after the first one ends.
    active = {"busy": False}

    async def handle(reader, writer):
        if result.done() or active["busy"]:
            try:
                writer.close()
            except Exception:                                   # noqa: BLE001
                pass
            return
        active["busy"] = True
        peer = writer.get_extra_info("peername")

        def log(text):
            _debug_log(debug_handle, text)

        log("connected from %s" % ((peer[0] if peer else "?"),))
        host = pairing.PairableHost(reader, writer, identity, log=log)

        def pin(code):
            _say("")
            _say("  pairing code:  %s" % code)
            _say("  enter it on the TARGET now")
            log("PIN shown: %s" % code)

        try:
            info = await host.accept(pin)
            log("pair-setup done: peer=%r" % (info,))
            if not result.done():
                result.set_result((info, (peer[0] if peer else "").split("%", 1)[0]))
        except Exception as exc:                                # noqa: BLE001
            import traceback as _tb
            log("FAILED: %r" % (exc,))
            log(_tb.format_exc(limit=5))
            if not result.done():
                result.set_exception(exc)
        finally:
            active["busy"] = False
            try:
                writer.close()
            except Exception:                                   # noqa: BLE001
                pass

    # Bind IPv4 and IPv6 on the same port: the target may resolve the signer's
    # .local name to either family.  A throwaway server picks a free port first.
    probe = await asyncio.start_server(handle, "0.0.0.0", 0)
    port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()
    server = await asyncio.start_server(handle, host=None, port=port)
    txt = pairing.mdns_txt(identity)
    instructions = [
        "signer: advertising as BariSign",
        "target: Settings > Privacy & Security > Developer Mode > Paired Macs",
        "        (or Settings > Developer > Paired Macs)",
        "pick BariSign, then enter the code printed here",
    ]

    registration = None
    advertiser = None
    use_raw = raw or _ashell_limited()
    try:
        if use_raw:
            advertiser = raw_mdns.Advertiser(identity, port, target_ip).start()
            transports = advertiser.transports
        else:
            try:
                registration = mdns.register(mdns.PAIRABLE_HOST, "BariSign", port, txt)
                await registration.__aenter__()
                transports = "DNS-SD"
            except RuntimeError as exc:
                if "-65555" not in str(exc) and "NoAuth" not in str(exc):
                    raise
                registration = None
                advertiser = raw_mdns.Advertiser(identity, port, target_ip).start()
                transports = advertiser.transports
        _stage("Pairing", instructions + ["advertising via %s" % transports])
        try:
            return await asyncio.wait_for(result, timeout)
        except asyncio.TimeoutError:
            raise RuntimeError("timed out: the target never paired")
    finally:
        try:
            debug_handle.close()
        except Exception:                                       # noqa: BLE001
            pass
        if registration is not None:
            try:
                await registration.__aexit__(None, None, None)
            except Exception:                                   # noqa: BLE001
                pass
        if advertiser is not None:
            advertiser.stop()
        server.close()
        await server.wait_closed()


# --------------------------------------------------------------------------
# Target discovery
# --------------------------------------------------------------------------

def _sort_addresses(addresses):
    def key(address):
        try:
            import ipaddress
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
            return (parsed.is_link_local, parsed.version)
        except ValueError:
            return (True, 9)
    return sorted(addresses, key=key)


def _choose_host(services, udid, peer_ip, host=None, port=0):
    if host:
        return host, port
    candidates = []
    for service in services:
        properties = service.get("properties") or {}
        identifier = properties.get("identifier") or ""
        addresses = _sort_addresses(service.get("addresses") or [])
        if not addresses or not service.get("port"):
            continue
        candidates.append((service, identifier, addresses))
    if not candidates:
        return "", 0
    if udid:
        wanted = udid.lower()
        for service, identifier, addresses in candidates:
            if identifier.lower() == wanted or wanted in identifier.lower():
                return addresses[0], service["port"]
    if peer_ip:
        for service, _identifier, addresses in candidates:
            if peer_ip in addresses:
                return peer_ip, service["port"]
    if len(candidates) == 1:
        return candidates[0][2][0], candidates[0][0]["port"]
    _say("")
    _say("  more than one device advertises pairing:")
    for index, (service, identifier, addresses) in enumerate(candidates, 1):
        name = (service.get("properties") or {}).get("name") or identifier or "?"
        _say("    %d. %s  %s" % (index, name, addresses[0]))
    _say("")
    try:
        choice = int(_ask("  number: ", "1"))
    except ValueError:
        choice = 1
    choice = max(1, min(len(candidates), choice))
    service = candidates[choice - 1]
    return service[2][0], service[0]["port"]


async def find_service(udid, peer_ip, host, port, timeout=6):
    if host:
        return host, port
    # Raises on a-Shell (DNSServiceBrowse -65555): the caller falls back
    # silently to the paired address instead of printing API internals.
    services = mdns.browse(mdns.REMOTE_PAIRING, timeout=timeout)
    return _choose_host(services, udid, peer_ip, host, port)


async def _tcp_open(host, port, timeout=1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:                                           # noqa: BLE001
        return None
    try:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:                                       # noqa: BLE001
            pass
    except Exception:                                           # noqa: BLE001
        pass
    return port


async def scan_ports(host, start=49152, count=48, timeout=1.0, batch=24):
    """Find open TCP ports near the usual RPPairing port (it moves at boot).

    Closed ports on a LAN RST immediately, so a /48 sweep in batches is fast.
    Returns open ports, 49152 first when open.
    """
    found = []
    ports = [start + offset for offset in range(count)]
    for chunk in range(0, len(ports), batch):
        results = await asyncio.gather(
            *[_tcp_open(host, port, timeout) for port in ports[chunk:chunk + batch]])
        found.extend(port for port in results if port is not None)
        if found and chunk >= batch:
            break
    return sorted(found, key=lambda p: (p != start, p))


async def resolve_port(host, port):
    """Return usable _remotepairing port(s): the given one, else a quick scan."""
    if port:
        return [port]
    if await _tcp_open(host, 49152):
        return [49152]
    found = await scan_ports(host)
    if not found:
        raise RuntimeError("no pairing port answered on %s" % host)
    return found


def _id_match(value, *candidates):
    """True when a handshake identifier names the same device as a saved UDID."""
    wanted = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if not wanted:
        return False
    for candidate in candidates:
        other = re.sub(r"[^0-9a-f]", "", str(candidate or "").lower())
        if other and other == wanted:
            return True
    return False


async def pair_fresh(identity, timeout, raw=False, target_ip=""):
    """Run one device-initiated pairing; save record+UDID; return (record, udid, peer_ip, info)."""
    info, peer_ip = await pair_target(timeout, identity, raw=raw, target_ip=target_ip)
    pseudo = pairing.PairingRecord(identity, info)
    record_path = save_record(pseudo)
    udid = normalise_udid(info.get("udid", ""))
    save_state(paired=True, udid=udid, peer_ip=peer_ip, paired_at=int(time.time()),
               peer_name=info.get("name", ""), record=record_path)
    return rpp_tunnel.load_record(record_path), udid, peer_ip, info


def registry_touch_peer(host, udid="", identifier=""):
    """Remember where a device answered, so the next run skips the sweep."""
    import time as _time
    entries = load_registry()
    changed = False
    for entry in entries:
        if (udid and _norm_id(entry.get("udid")) == _norm_id(udid)) or \
           (identifier and _norm_id(entry.get("identifier")) == _norm_id(identifier)):
            entry["peer_ip"] = host
            entry["last_used"] = int(_time.time())
            changed = True
    if changed:
        save_registry(entries)


async def sweep_target(record, udid=""):
    """Look for our target on the signer's /24 without any address from the user.

    Sweeps port 49152 across the subnet, handshakes each open host (no UI on
    the target) and returns ("match", (host, port)), ("opens", [hosts]) when
    something answered but nothing matched, or ("none", None). Stale DHCP
    leases make the saved peer_ip wrong; this needs no lookup in Settings.
    """
    me = raw_mdns.wifi_ipv4()
    parts = me.split(".") if me else []
    if len(parts) != 4:
        return "none", None
    try:
        if int(parts[3]) < 0 or int(parts[3]) > 255:
            return "none", None
    except ValueError:
        return "none", None
    prefix = ".".join(parts[:3])
    _say("  sweep        looking for the target on this Wi-Fi")
    candidates = ["%s.%d" % (prefix, i) for i in range(1, 255)
                  if "%s.%d" % (prefix, i) != me]

    async def check(ip):
        if await _tcp_open(ip, 49152, timeout=1.0):
            return ip
        return None

    open_hosts = []
    for chunk in range(0, len(candidates), 48):
        results = await asyncio.gather(
            *[check(ip) for ip in candidates[chunk:chunk + 48]])
        open_hosts.extend(ip for ip in results if ip)
    if not open_hosts:
        return "none", None
    want_udid = (record or {}).get("peer_udid") or udid
    want_identifier = (record or {}).get("peer_identifier", "")
    for host in open_hosts:
        peer = await rpp_tunnel.probe_handshake(host, 49152)
        if not peer:
            continue
        if _id_match(peer.get("identifier"), want_udid, want_identifier, udid):
            return "match", (host, 49152)
    return "opens", open_hosts


def _friendly_error(host, exc):
    """Translate transport gibberish into one actionable line."""
    text = str(exc)
    if ("0 bytes read" in text or "Connection reset" in text
            or "ConnectionTerminated" in text or "EOF" in text):
        return RuntimeError(
            "the target at %s closed the connection without answering "
            "(is it awake, unlocked and on the same Wi-Fi as the signer?)" % host)
    if "timed out" in text.lower() or "Timeout" in type(exc).__name__:
        return RuntimeError(
            "the target at %s did not answer "
            "(is it awake, unlocked and on the same Wi-Fi as the signer?)" % host)
    return exc


async def open_session(record, host, port, identity_udid=""):
    ports = await resolve_port(host, port)
    errors = []
    for candidate in ports:
        try:
            tunnel = await rpp_tunnel.open_tunnel(host, candidate, record)
        except Exception as exc:                                # noqa: BLE001
            errors.append("%s: %s" % (candidate, exc))
            continue
        stack = tcp6.TcpStack(tunnel["link"], tunnel["client_address"])
        await stack.start()
        try:
            connection = await stack.connect(tunnel["server_address"], tunnel["rsd_port"], timeout=15)
            services, properties, xpc = await remote_xpc.connect_rsd(connection, connection)
        except Exception:
            await stack.close()
            continue
        _say("  device       %s" % (properties.get("ProductType", "?")))
        return Session(tunnel, stack, services, properties, xpc)
    raise RuntimeError("pair-verify failed on %s (tried %s): %s"
                       % (host, ports, "; ".join(errors[:3])))


# --------------------------------------------------------------------------
# The tunnel / install flow
# --------------------------------------------------------------------------

class Session:
    def __init__(self, tunnel, stack, services, properties, xpc=None):
        self.tunnel = tunnel
        self.xpc = xpc
        self.stack = stack
        self.services = services
        self.properties = properties
        self.udid = normalise_udid(properties.get("UniqueDeviceID", ""))
        self.address = tunnel["server_address"]

    async def close(self):
        await self.stack.close()
        if self.xpc is not None:
            try:
                await self.xpc.close()
            except Exception:                                  # noqa: BLE001
                pass
        try:
            self.tunnel["stream"].close()
        except Exception:                                       # noqa: BLE001
            pass
        try:
            await self.tunnel["stream"].wait_closed()
        except Exception:                                       # noqa: BLE001
            pass


def _preflight_ipa(ipa, udid):
    """Fail fast when the signed IPA cannot install, before uploading 40 MB.

    Catches the classic lapse: signing with a then-valid 7-day free profile
    and installing after it expired — which installd reports only as a bare
    ApplicationVerificationFailed at 40%.
    """
    import signer
    try:
        with zipfile.ZipFile(ipa) as archive:
            names = [name for name in archive.namelist()
                     if name.startswith("Payload/") and name.endswith(".app/embedded.mobileprovision")
                     and name.count("/") == 2]
            if not names:
                raise DeviceServiceError(
                    "the signed IPA has no embedded profile; sign it again")
            blob = archive.read(names[0])
    except zipfile.BadZipFile:
        raise DeviceServiceError("not a readable IPA: %s" % ipa)
    try:
        profile = signer.parse_mobileprovision_blob(blob)
    except Exception as exc:                                    # noqa: BLE001
        raise DeviceServiceError("cannot read the embedded profile: %s" % exc)
    problems = signer.install_preflight(profile, udid)
    if problems:
        raise DeviceServiceError("; ".join(problems))


async def install(session, ipa, record_path):
    install_port = remote_xpc.service_port(session.services, device_services.INSTALL_SERVICE)
    afc_port = remote_xpc.service_port(session.services, device_services.AFC_SERVICE)
    bundle_id = ipa_bundle_id(ipa)
    _preflight_ipa(ipa, session.udid)

    def progress(done, total):
        percent = int(done * 100 / max(1, total))
        sys.stdout.write("\r\033[2K  install      uploading %3d%%" % percent)
        sys.stdout.flush()

    def log(text):
        sys.stdout.write("\r\033[2K  install      %s" % text)
        sys.stdout.flush()

    await device_services.install_ipa(
        session.stack, session.address, install_port, afc_port, ipa,
        progress=progress,
        log=log)
    sys.stdout.write("\r\033[2K  install      ok\n")
    sys.stdout.flush()

    if record_path and os.path.isfile(record_path) and bundle_id:
        await _write_pairing_file(session, bundle_id, record_path)


REMOTE_KEYS = ("public_key", "private_key", "identifier", "alt_irk")


def _remote_only(record_path):
    """The RPPairing record alone, as an XML plist (what the apps read).

    Matches idevice's RpPairingFile layout exactly: public_key, private_key
    (32 bytes each), identifier, and alt_irk when present. Aliases
    (host_identifier/...) and peer_* metadata stay in state's copies only:
    SideStore nightlies reject a file holding both protocols as ambiguous,
    and AltStore takes an RPPairing record on its own.
    """
    with open(record_path, "rb") as handle:
        record = plistlib.loads(handle.read())
    return plistlib.dumps(
        {key: record[key] for key in REMOTE_KEYS if record.get(key)},
        fmt=plistlib.FMT_XML)


def pairing_target(bundle_id):
    """(documents_only, [remote names], prefs path or None) for a bundle id.

    Verified 2026-11-16 against current upstreams: SideStore's AppConstants
    (ALTPairingFile.mobiledevicepairing; nightlies >= 0.7.0-20260920 read a
    per-protocol PairingFile_RemoteRP.plist instead and only load it once an
    import clears isPairingReset and records activePairingProtocol — so the
    matching preferences are written too), SideInstaller's PairingTargets table
    (LiveContainer's built-in SideStore lives under SideStore/Documents/,
    legacy file still read; its prefs live in its own home folder), and
    AltStore 2.3.1+ (Documents/ALTPairingFile.plist, RPPairing only, takes it
    into its Keychain itself; beta explicitly out). Custom IPAs are
    intentionally unmatched.
    """
    base = bundle_id or ""
    if ".Beta" in base:
        return None  # AltStore Beta is a different app (SideInstaller table)
    if base == "com.rileytestut.AltStore" or base.startswith("com.rileytestut.AltStore."):
        return True, ("ALTPairingFile.plist",), None
    if base == "com.SideStore.SideStore" or base.startswith("com.SideStore.SideStore."):
        return True, ("ALTPairingFile.mobiledevicepairing", "PairingFile_RemoteRP.plist"), \
            "Library/Preferences/%s.plist" % base
    if base == "com.kdt.livecontainer" or base.startswith("com.kdt.livecontainer."):
        return False, ("SideStore/Documents/ALTPairingFile.mobiledevicepairing",
                       "SideStore/Documents/PairingFile_RemoteRP.plist"), \
            "Documents/SideStore/Library/Preferences/com.SideStore.SideStore.plist"
    return None


def merge_sidestored_prefs(existing):
    """Preferences enabling the dropped RPPairing file, preserving the rest.

    Mirrors SideStore's own import (isPairingReset off, active protocol set).
    `existing` is the raw file or b"" when absent; None means leave it alone.
    """
    if existing:
        try:
            prefs = plistlib.loads(existing)
        except Exception:                                       # noqa: BLE001
            return None
        if not isinstance(prefs, dict):
            return None
    else:
        prefs = {}
    if prefs.get("isPairingReset") is False and prefs.get("activePairingProtocol") == "rppairing":
        return None
    prefs["isPairingReset"] = False
    prefs["activePairingProtocol"] = "rppairing"
    return plistlib.dumps(prefs, fmt=plistlib.FMT_XML)


async def _write_pairing_file(session, bundle_id, record_path):
    target = pairing_target(bundle_id)
    if target is None:
        return
    documents_only, names, prefs_name = target
    try:
        data = _remote_only(record_path)
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! pairing file not written into the app: %s" % exc)
        return
    port = remote_xpc.service_port(session.services, device_services.HOUSE_ARREST_SERVICE)
    try:
        afc, connection = await device_services.vend_container(
            session.stack, session.address, port, bundle_id, documents_only=documents_only)
        try:
            for name in names:
                directory = os.path.dirname(name)
                if directory:
                    await afc.makedirs("/" + directory)
                await afc.upload("/" + name, data)
            _say("  pairing file written into %s" % bundle_id)
        finally:
            await connection.close()
        if prefs_name is not None:
            # New SideStore nightlies ignore the file until an import clears
            # isPairingReset and records the protocol; write the same two keys
            # its own import would write. Library/ lives outside Documents, so
            # this needs its own whole-container vend.
            whole, whole_connection = await device_services.vend_container(
                session.stack, session.address, port, bundle_id, documents_only=False)
            try:
                directory = os.path.dirname(prefs_name)
                if directory:
                    await whole.makedirs("/" + directory)
                merged = merge_sidestored_prefs(await whole.download("/" + prefs_name))
                if merged is not None:
                    await whole.upload("/" + prefs_name, merged)
            finally:
                await whole_connection.close()
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! pairing file not written into the app: %s" % exc)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _open_preview(path):
    """Open a-Shell's preview so the share sheet can AirDrop the file."""
    import shlex
    marker = os.environ.get("TERM_PROGRAM", "").lower()
    ashell = (sys.platform == "ios" or sys.platform.startswith("darwin")
              or "a-shell" in marker or "ashell" in marker)
    if ashell and sys.stdin.isatty():
        os.system("view %s" % shlex.quote(path))
    else:
        _say("  file         %s" % path)


def _pick_registry_entry(entries, purpose):
    """Ask which paired device, newest pairing first. Returns an entry."""
    _stage("Pairing", ["%s — whose record?" % purpose])
    for index, entry in enumerate(entries, 1):
        model = entry.get("model") or ""
        _say("  %d  %s%s  %s" % (index, entry.get("name") or "target",
                                 (" (%s)" % model) if model else "",
                                 entry.get("udid") or ""))
    _say("")
    choice = _ask("  number: ", "1")
    if choice.isdigit() and 1 <= int(choice) <= len(entries):
        return entries[int(choice) - 1]
    return entries[0]


def export_record(dest):
    """Copy a pairing file out for AirDrop / manual in-app import.

    With no path, asks which paired device's record to export, writes it
    under ~/Documents and opens the preview so it can be shared at once.
    """
    if dest and not dest.startswith("-"):
        record = _load_record()
        if record is None:
            _say("  ! no pairing file yet; pair first")
            return 2
        with open(RECORD_PATH, "rb") as handle:
            data = handle.read()
        out = os.path.abspath(os.path.expanduser(dest))
    else:
        entries = [entry for entry in load_registry() if os.path.isfile(entry.get("file", ""))]
        if not entries:
            _say("  ! no paired device yet; pair first")
            return 2
        if len(entries) > 1 and sys.stdin.isatty():
            picked = _pick_registry_entry(entries, "export pairing file")
        else:
            picked = entries[0]
        with open(picked["file"], "rb") as handle:
            data = handle.read()
        udid = normalise_udid(picked.get("udid", ""))
        out = os.path.join(os.path.expanduser("~"), "Documents",
                           "BariSign-Pairing-%s.mobiledevicepairing" % (udid[:8] or "device"))
    directory = os.path.dirname(out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        with open(out, "wb") as handle:
            handle.write(data)
    except OSError as exc:                                      # noqa: BLE001
        _say("  ! cannot write %s: %s" % (out, exc))
        return 1
    _say("  exported     %s" % display_path(out))
    _open_preview(out)
    return 0


def check():
    _say("  python       %s" % platform.python_version())
    try:
        import cryptography
        _say("  cryptography %s" % getattr(cryptography, "__version__", "?"))
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! cryptography: %s" % exc)
        return 1
    try:
        import tls_psk, tcp6, remote_xpc, device_services, pairing, rpp_tunnel, mdns  # noqa: F401
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! engine import failed: %s: %s" % (type(exc).__name__, exc))
        return 1
    _say("  engine       pure Python, no qh3/sslpsk/native wheel")
    _say("  tunnel       TLS 1.2 PSK 0x00AF/0x008C + userspace TCP")
    _say("  status       ready (device path untested)")
    return 0


def _record_identity():
    identity = pairing.HostIdentity.load_or_create(IDENTITY_PATH)
    return identity


def _load_record():
    try:
        return rpp_tunnel.load_record(RECORD_PATH)
    except Exception:                                           # noqa: BLE001
        return None


async def run_devmode_command(session, action):
    """Standalone `pair --devmode status|show|on` on an open session."""
    action = (action or "status").lower()
    if action not in ("status", "show", "on"):
        _say("  ! --devmode takes status, show or on")
        return 2
    try:
        on = await devmode.status(session.stack, session.address, session.services)
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! status unreadable: %s" % exc)
        return 1
    if on:
        _say("  devmode      on (nothing sent)")
        return 0
    if action == "status":
        _say("  devmode      %s" % ("off" if on is False else "unknown"))
        return 0
    if action == "on":
        choice = _ask("  restart the device now to turn it on? y/N: ", "n")
        if choice.strip().lower() not in ("y", "yes"):
            _say("  nothing sent")
            return 0
        try:
            await devmode.turn_on(session.stack, session.address, session.services)
        except devmode.DevmodeError as exc:
            if str(exc) == "passcode-set":
                _say("  passcode is set: iOS refuses; showing the switch instead")
            else:
                _say("  ! %s" % exc)
                return 1
        else:
            _say("  restarting: re-run to verify")
            return 0
    try:
        await devmode.show_switch(session.stack, session.address, session.services)
    except devmode.DevmodeError as exc:                         # noqa: BLE001
        _say("  ! %s" % exc)
        return 1
    _say("  switch shown: Settings > Privacy & Security > Developer Mode")
    return 0


async def ensure_devmode(session, host, port, record, udid):
    """Developer Mode must be ON for the installed app to launch.

    Shows the switch when it is off or hidden (no restart). Turning it on
    always restarts the iPhone, which kills this run — so after show/turn-on
    the flow ends with a restart card and the user re-runs: pairing record,
    download and portal data are all saved, so the next run jumps straight
    past them. Returns the session, or None when a restart comes first.
    """
    try:
        on = await devmode.status(session.stack, session.address, session.services)
    except Exception as exc:                                    # noqa: BLE001
        _say("  devmode      status unreadable (%s); continuing" % exc)
        return session
    if on:
        _say("  devmode      on")
        return session
    _stage("Developer Mode", ["off or hidden: asking iOS to show the switch"])
    try:
        await devmode.show_switch(session.stack, session.address, session.services)
    except devmode.DevmodeError as exc:                         # noqa: BLE001
        raise _friendly_error(host, exc)
    _say("  switch shown: Settings > Privacy & Security > Developer Mode")
    choice = _ask("  turn it on now instead (restarts immediately)? y/N: ", "n")
    if choice.strip().lower() in ("y", "yes"):
        try:
            await devmode.turn_on(session.stack, session.address, session.services)
        except devmode.DevmodeError as exc:                     # noqa: BLE001
            if str(exc) == "passcode-set":
                _say("  passcode is set: turn it on by hand in Settings")
            else:
                raise _friendly_error(host, exc)
        else:
            _stage("Done", ["restarting: re-run after boot",
                            "everything is saved; it jumps back here"])
            return None
    _say("  turn ON Developer Mode in Settings (it restarts the iPhone),")
    _say("  then re-run: everything is saved and it jumps back here.")
    return None


async def _run(args):
    state = load_state()
    identity = _record_identity()
    record = _load_record()
    udid = normalise_udid(args.get("udid") or state.get("udid") or "")
    peer_ip = state.get("peer_ip") or ""
    timeout = args.get("timeout") or 300

    if args.get("repair"):
        # A fresh host identity is the only way to make an already-paired target
        # offer a new pairing prompt.
        identity = pairing.HostIdentity.generate()
        identity.save(IDENTITY_PATH)
        record = None
    if args.get("import"):
        source = os.path.expanduser(args["import"])
        try:
            imported = rpp_tunnel.load_record(source)
        except Exception as exc:                            # noqa: BLE001
            _say("  ! cannot read the pairing file %s: %s" % (source, exc))
            return 2
        record_path = save_record(imported)
        imported_udid = normalise_udid(imported.get("peer_udid") or "")
        imported_info = {"udid": imported_udid,
                         "name": imported.get("peer_name") or "",
                         "model": imported.get("peer_model") or "",
                         "identifier": imported.get("peer_identifier") or ""}
        registry_upsert(imported_info, record_path, "")
        record = imported
        udid = normalise_udid(args.get("udid") or imported_udid or udid)
        save_state(paired=True, udid=udid, record=RECORD_PATH, paired_at=int(time.time()))
        _say("  imported     %s" % source)
        if udid:
            _say("  UDID         %s" % udid)
        if args.get("pair_only"):
            _say("  done         pairing file imported")
            return 0

    entries = registry_migrate()
    just_paired = False
    if record is None:
        # No record at all (fresh run or --repair): pair now, no menu.
        try:
            record, udid, peer_ip, info = await pair_fresh(
                identity, timeout,
                raw=args.get("raw", False), target_ip=args.get("target_ip", ""))
        except Exception as exc:                            # noqa: BLE001
            text = str(exc)
            if "-65555" in text or "NoAuth" in text or "NSBonjourServices" in text:
                _say("  ! a-Shell cannot use Bonjour here; using raw advertisement")
                return 2
            raise
        entries = registry_upsert(info, RECORD_PATH, peer_ip)
        just_paired = True

    loopback = bool(args.get("loopback"))
    if loopback:
        # EXPERIMENTAL same-device path: the tunnel/install engine runs
        # unchanged against the LocalDevVPN loopback instead of the Wi-Fi
        # target. No discovery, no sweep, no menu.
        host = args.get("loopback_host") or LOOPBACK_HOST
        _stage("Loopback", [
            "same-device experiment via %s" % host,
            "LocalDevVPN must be installed and connected",
        ])
        try:
            port = await loopback_probe(host, args.get("loopback_port") or 0)
        except RuntimeError as exc:
            _say("  ! %s" % exc)
            return 2
        _say("  loopback     %s:%d answered" % (host, port))
        udid = normalise_udid(args.get("udid") or state.get("udid") or udid)
        save_state(peer_ip=host)
    else:
        host, port = "", 0

    if not loopback:
        explicit_host = args.get("host", "") or ""
        explicit_udid = normalise_udid(args.get("udid") or "")
        interactive = sys.stdin.isatty()
        if explicit_host:
            host, port = explicit_host, args.get("port", 0) or 0
        elif explicit_udid:
            match = next((entry for entry in entries
                          if _norm_id(entry.get("udid")) == _norm_id(explicit_udid)), None)
            if match is not None:
                record, udid = registry_activate(match)
            host, port = match.get("peer_ip", "") if match else "", 0
            if not host:
                host, port = state.get("peer_ip") or peer_ip or "", 0
        elif entries and interactive and not just_paired:
            kind, picked = choose_device(entries)
            if kind == "new":
                try:
                    record, udid, peer_ip, info = await pair_fresh(
                        identity, timeout,
                        raw=args.get("raw", False), target_ip=args.get("target_ip", ""))
                except Exception as exc:                        # noqa: BLE001
                    text = str(exc)
                    if "-65555" in text or "NoAuth" in text or "NSBonjourServices" in text:
                        _say("  ! a-Shell cannot use Bonjour here; using raw advertisement")
                        return 2
                    raise
                entries = registry_upsert(info, RECORD_PATH, peer_ip)
                just_paired = True
                host, port = peer_ip, 0
            else:
                record, udid = registry_activate(picked)
                host, port = picked.get("peer_ip", ""), 0
        else:
            if entries:
                record, udid = registry_activate(entries[0])
                host, port = entries[0].get("peer_ip", ""), 0
            else:
                host, port = state.get("peer_ip") or peer_ip or "", 0
        if not host:
            host, port = state.get("peer_ip") or peer_ip or "", 0

    # a-Shell can neither advertise nor browse Bonjour (-65555 on both), so
    # skip discovery there entirely: the paired address plus scans replace it.
    # Any browse failure (first -65555 included) is remembered, so later runs
    # do not even try.
    if not host and not _ashell_limited() and not load_state().get("bonjour_blocked"):
        for _attempt in range(2):
            try:
                host, port = await find_service(udid, peer_ip, "", 0, timeout=4)
            except Exception:                                   # noqa: BLE001
                save_state(bonjour_blocked=True)
                host, port = "", 0
                break
            if host and (port or peer_ip):
                break
            await asyncio.sleep(2)
    if not host:
        host = peer_ip or load_state().get("peer_ip") or ""
    port = port or 0
    if not host:
        _stage("Pairing", ["the target was not found"])
        _say("  pass its Wi-Fi address directly:")
        _say("  target: Settings > Wi-Fi > (i) > IP Address, then")
        _say("  barisign pair --host <target-ip>")
        return 2
    _stage("Pairing", ["target:  %s" % host])

    session = None
    explicit = bool(args.get("host", "")) or loopback
    try:
        while True:
            try:
                session = await asyncio.wait_for(open_session(record, host, port, udid), 120)
                break
            except Exception as exc:                            # noqa: BLE001
                first_error = exc
                if args.get("pair_only") and udid:
                    _say("  ! tunnel/UDID check failed: %s" % exc)
                    _say("  UDID saved from the pairing: %s" % udid)
                    save_state(udid=udid, paired=True)
                    return 0
                if explicit:
                    raise _friendly_error(host, exc)
                status, payload = "none", None
                try:
                    status, payload = await sweep_target(record, udid)
                except Exception:                               # noqa: BLE001
                    status, payload = "none", None
                if status == "match":
                    host, port = payload
                    _stage("Pairing", ["target:  %s:%d" % (host, port)])
                    save_state(peer_ip=host)
                    peer_id = record.get("peer_identifier", "") if isinstance(record, dict) else ""
                    peer_udid = record.get("peer_udid", "") if isinstance(record, dict) else udid
                    registry_touch_peer(host, peer_udid, peer_id)
                    continue
                # Nothing usable on this Wi-Fi: ask instead of dying.
                _say("  the target did not answer.")
                _say("  same Wi-Fi on both devices? target awake and unlocked?")
                _say("  1  try again")
                _say("  2  pair again (fresh prompt on the target)")
                if not sys.stdin.isatty():
                    raise _friendly_error(host, first_error)
                choice = _ask("  choose 1-2: ", "1")
                if choice == "2":
                    try:
                        identity = pairing.HostIdentity.generate()
                        identity.save(IDENTITY_PATH)
                        record, udid, peer_ip, info = await pair_fresh(identity, timeout)
                    except Exception as exc2:                       # noqa: BLE001
                        raise _friendly_error(host, exc2)
                    entries = registry_upsert(info, RECORD_PATH, peer_ip)
                    host, port = peer_ip, 0
                    if not host:
                        raise _friendly_error(host, first_error)
                    continue
                # try again: loop re-scans and re-sweeps
                continue
        if session.udid:
            if udid and udid != session.udid:
                _say("  ! the tunnel reports a different UDID than the pairing record")
            udid = session.udid
            save_state(udid=udid, paired=True)
        if not udid:
            _say("  ! could not read the target's UDID from the tunnel")
            return 2
        if args.get("devmode"):
            return await run_devmode_command(session, args.get("devmode"))
        device = session.properties.get("ProductType", "") or "device"
        if args.get("pair_only"):
            _stage("Pairing", [
                "target:  %s" % host,
                "device:  %s" % device,
                "UDID:    %s" % udid,
                "pairing file saved",
            ])
            return 0
        _stage("Pairing", [
            "target:  %s" % host,
            "device:  %s" % device,
            "UDID:    %s" % udid,
        ])

        explicit = args.get("ipa") or ""
        if explicit and not os.path.isfile(explicit):
            _say("  ! not found: %s" % explicit)
            return 2
        ipa = find_ipa(explicit)
        if not ipa:
            _say("  ! no signed IPA found")
            _say("    sign first (barisign sign), or pass --ipa FILE")
            return 2
        if not args.get("no_devmode"):
            session = await ensure_devmode(session, host, port, record, udid)
            if session is None:
                return 0
        _stage("Install", ["installing:  %s" % os.path.basename(ipa)])
        await asyncio.wait_for(install(session, ipa, RECORD_PATH), 900)
        done_lines = [
            "installed:  %s" % os.path.basename(ipa),
            "on the target: Settings > General > VPN & Device Management",
            "trust the developer, then open the app",
            "pairing file: barisign pair --export FILE for a manual copy",
        ]
        variant_id = load_state().get("variant", "")
        if "nightly" in variant_id and "sidestore" in ipa_bundle_id(ipa).lower():
            done_lines.append("SideStore nightly: if it asks, import the pairing")
            done_lines.append("file from its own Settings page")
        _stage("Done", done_lines)
        return 0
    finally:
        if session is not None:
            await session.close()


def main(argv):
    if "--help" in argv or "-h" in argv:
        # Two short lines per flag: an iPhone upright is ~40 columns.
        for flag, text in (
                ("pair", "install newest signed IPA"),
                ("pair --ipa FILE", "install this file"),
                ("pair --pair-only", "pair only, save UDID"),
                ("pair --udid UDID", "use paired target"),
                ("pair --import FILE", "pairing file, other host"),
                ("pair --host IP", "Wi-Fi target address"),
                ("pair --loopback", "same-device install"),
                ("pair --loopback-port P", "loopback port, or probe"),
                ("pair --loopback-host IP", "default 10.7.0.1"),
                ("pair --keep-awake", "speech holds the app"),
                ("pair --devmode CMD", "status, show or on"),
                ("pair --no-devmode", "skip devmode check"),
                ("pair --raw-mdns", "force raw advertisement"),
                ("pair --target-ip IP", "unicast mDNS extra"),
                ("pair --export [FILE]", "copy pairing file out"),
                ("pair --timeout N", "give up after N s"),
                ("pair --check", "verify engine imports"),
                ("pair --setup", "verify engine, no download")):
            _say("barisign %s" % flag)
            _say("    %s" % text)
        return 0

    def value(flag, default=""):
        if flag in argv:
            position = argv.index(flag) + 1
            if position < len(argv):
                return argv[position]
        return default

    args = {
        "ipa": value("--ipa"),
        "udid": value("--udid"),
        "host": value("--host"),
        "port": int(value("--port", "0") or 0),
        "import": value("--import"),
        "target_ip": value("--target-ip"),
        "loopback": "--loopback" in argv,
        "loopback_host": value("--loopback-host") or LOOPBACK_HOST,
        "loopback_port": int(value("--loopback-port", "0") or 0),
        "devmode": value("--devmode"),
        "no_devmode": "--no-devmode" in argv,
        "raw": "--raw-mdns" in argv,
        "timeout": int(value("--timeout", "0") or 0) or None,
        "pair_only": "--pair-only" in argv,
        "repair": "--repair" in argv,
        "debug": "--debug" in argv,
        "export": value("--export"),
    }
    if "--export" in argv:
        return export_record(args["export"])
    if args["host"] and not args["port"]:
        # The device's RPPairing service listens on 49152 (SideStore/LocalDevVPN
        # documents the same port); allow --port when it differs.
        args["port"] = 49152
    if "--check" in argv:
        return check()
    if "--setup" in argv or "--ensure" in argv:
        return check()
    stop_awake = None
    if "--keep-awake" in argv:
        stop_awake = keep_awake_start()
    try:
        try:
            return asyncio.run(_run(args))
        finally:
            if stop_awake is not None:
                stop_awake()
    except KeyboardInterrupt:
        _say("")
        return 130
    except Exception as exc:                                    # noqa: BLE001
        # A moving line (pairing code, upload, install status) may be open;
        # close it first so the error starts on its own clean line.
        sys.stdout.write("\n")
        sys.stdout.flush()
        _say("  ! %s" % exc)
        if args["debug"]:
            traceback.print_exc()
        else:
            _say("  (rerun with --debug for the full traceback)")
        try:
            log = os.path.join(STATE_DIR, "pair_debug.log")
            if (os.path.isfile(log) and time.time() - os.path.getmtime(log) < 600
                    and os.path.getsize(log) > 0):
                _say("  log  %s" % display_path(log))
        except Exception:                                       # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
