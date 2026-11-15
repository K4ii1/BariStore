#!/usr/bin/env python3
# =============================================================================
#  BariSign — pair the target and install the signed IPA (MIT)
#
#  Runs on the SIGNER inside a-Shell.  No pip, no qh3, no sslpsk, no native
#  wheel: every protocol piece is implemented in pure Python on top of the
#  cryptography 3.4.8 that a-Shell ships.
#
#      sh bin/barisign pair                 pair (if needed) and install
#      sh bin/barisign pair --pair-only     pair, save the UDID, stop
#      sh bin/barisign pair --check         verify the pure engine imports
#      sh bin/barisign pair --ipa FILE      install a specific signed IPA
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
import sys
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
import mdns
import pairing
import raw_mdns
import remote_xpc
import rpp_tunnel
import tcp6


def _say(text=""):
    print(text, flush=True)


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
    for pattern in (os.path.join(STATE_DIR, "*-signed.ipa"),
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

    async def handle(reader, writer):
        if result.done():
            writer.close()
            return
        peer = writer.get_extra_info("peername")

        def log(text):
            _debug_log(debug_handle, text)

        log("connected from %s" % ((peer[0] if peer else "?"),))
        host = pairing.PairableHost(reader, writer, identity, log=log)

        def pin(code):
            _say("")
            _say("  pairing code:  %s" % code)
            _say("  enter it on the TARGET now")
            _say("")
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
    _say("")
    _say("  signer: advertising as BariSign")
    _say("  target: Settings > Privacy & Security > Developer Mode > Paired Macs")
    _say("          (or Settings > Developer > Paired Macs)")
    _say("          pick BariSign, then enter the code printed here")
    _say("")

    registration = None
    advertiser = None
    use_raw = raw or _ashell_limited()
    try:
        if use_raw:
            advertiser = raw_mdns.Advertiser(identity, port, target_ip).start()
            _say("  advertising  raw %s from %s"
                 % (advertiser.transports, advertiser.ipv4))
        else:
            try:
                registration = mdns.register(mdns.PAIRABLE_HOST, "BariSign", port, txt)
                await registration.__aenter__()
            except RuntimeError as exc:
                if "-65555" not in str(exc) and "NoAuth" not in str(exc):
                    raise
                _say("  ! DNS-SD is blocked in a-Shell; trying raw multicast+broadcast")
                registration = None
                advertiser = raw_mdns.Advertiser(identity, port, target_ip).start()
                _say("  advertising  raw %s from %s"
                     % (advertiser.transports, advertiser.ipv4))
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
        choice = int(input("  number: ").strip() or "1")
    except (ValueError, EOFError):
        choice = 1
    choice = max(1, min(len(candidates), choice))
    service = candidates[choice - 1]
    return service[2][0], service[0]["port"]


async def find_service(udid, peer_ip, host, port, timeout=6):
    if host:
        return host, port
    try:
        services = mdns.browse(mdns.REMOTE_PAIRING, timeout=timeout)
    except Exception as exc:                                    # noqa: BLE001
        # a-Shell cannot browse (DNSServiceBrowse -65555, same allowlist as
        # registration). Fall back to the target IP seen on the pairing
        # connection; the port is found by scan below.
        _say("  ! Bonjour browse unavailable (%s); using the paired address" % exc)
        services = []
    if services:
        return _choose_host(services, udid, peer_ip, host, port)
    if peer_ip:
        return peer_ip, 0
    return "", 0


async def _tcp_open(host, port, timeout=1.5):
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


async def scan_ports(host, start=49152, count=48, timeout=1.5, batch=16):
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
    _say("  scan         probing the target for its pairing port")
    found = await scan_ports(host)
    if not found:
        raise RuntimeError("no pairing port answered on %s (target asleep or off-Wi-Fi?)" % host)
    _say("  scan         open: %s" % ", ".join(str(p) for p in found[:6]))
    return found


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
            connection = await stack.connect(tunnel["server_address"], tunnel["rsd_port"], timeout=20)
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


async def install(session, ipa, record_path):
    install_port = remote_xpc.service_port(session.services, device_services.INSTALL_SERVICE)
    afc_port = remote_xpc.service_port(session.services, device_services.AFC_SERVICE)
    bundle_id = ipa_bundle_id(ipa)
    _say("  installing   %s" % os.path.basename(ipa))

    def progress(done, total):
        percent = int(done * 100 / max(1, total))
        sys.stdout.write("\r  upload       %3d%%" % percent)
        sys.stdout.flush()

    await device_services.install_ipa(
        session.stack, session.address, install_port, afc_port, ipa,
        progress=progress,
        log=lambda text: _say("\r  install      %s" % text))
    _say("\r  install      ok")

    if not bundle_id:
        bundle_id = ipa_bundle_id(ipa)
    if record_path and os.path.isfile(record_path) and bundle_id:
        await _write_pairing_file(session, bundle_id, record_path)


async def _write_pairing_file(session, bundle_id, record_path):
    with open(record_path, "rb") as handle:
        data = handle.read()
    if bundle_id.startswith("com.altstore.AltStore"):
        documents_only, names = True, ("ALTPairingFile.plist", "ALTPairingFile.mobiledevicepairing")
    elif bundle_id.startswith("com.SideStore.SideStore"):
        documents_only, names = True, ("ALTPairingFile.mobiledevicepairing", "ALTPairingFile.plist")
    elif bundle_id.startswith("com.kdt.livecontainer"):
        documents_only, names = False, ("SideStore/Documents/ALTPairingFile.mobiledevicepairing",)
    else:
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
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! pairing file not written into the app: %s" % exc)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

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
        save_record(imported)
        record = imported
        udid = normalise_udid(args.get("udid") or imported.get("peer_udid") or udid)
        save_state(paired=True, udid=udid, record=RECORD_PATH)
        _say("  imported     %s" % source)
        if udid:
            _say("  UDID         %s" % udid)
        if args.get("pair_only"):
            _say("  done         pairing file imported")
            return 0
    if record is None:
        _say("  no pairing file yet; pairing the target first")
        try:
            info, peer_ip = await pair_target(timeout, identity,
                                              raw=args.get("raw", False),
                                              target_ip=args.get("target_ip", ""))
        except Exception as exc:                            # noqa: BLE001
            text = str(exc)
            if "-65555" in text or "NoAuth" in text or "NSBonjourServices" in text:
                _say("  ! a-Shell cannot advertise the pairing service")
                _say("    DNSServiceRegister returned -65555 (NoAuth).")
                _say("    iOS only allows Bonjour types listed in the app's")
                _say("    NSBonjourServices; a-Shell has no entry for")
                _say("    _remotepairing-pairable-host._tcp, and a signed app's")
                _say("    Info.plist cannot be changed from Python.")
                _say("")
                _say("  This blocks discovery in Settings > Developer > Paired Macs.")
                _say("  Run: python3 poc/bonjour_check.py")
                _say("  Options are in docs/NEXT_SESSION.md (pairing host with the")
                _say("  right Info.plist, or a pairing record obtained elsewhere).")
                return 2
            raise
        pseudo = pairing.PairingRecord(identity, info)
        record_path = save_record(pseudo)
        udid = normalise_udid(info.get("udid", ""))
        save_state(paired=True, udid=udid, peer_ip=peer_ip,
                   peer_name=info.get("name", ""), record=record_path)
        _say("  paired       %s" % (info.get("name") or "target"))
        _say("  UDID         %s" % (udid or "(will read it from the tunnel)"))
        record = rpp_tunnel.load_record(record_path)
    else:
        _say("  pairing file %s" % RECORD_PATH)

    host, port = args.get("host", ""), args.get("port", 0)
    if not host:
        for attempt in range(3):
            host, port = await find_service(udid, peer_ip, "", 0, timeout=4)
            if host and (port or peer_ip):
                break
            await asyncio.sleep(2)
    if not host:
        _say("  ! the target was not found")
        _say("    pass its Wi-Fi address directly:")
        _say("    target: Settings > Wi-Fi > (i) > IP Address, then")
        _say("    sh bin/barisign pair --host <target-ip>")
        return 2
    if port:
        _say("  target       %s:%d" % (host, port))

    session = None
    try:
        try:
            session = await asyncio.wait_for(open_session(record, host, port, udid), 90)
        except Exception as exc:                                # noqa: BLE001
            if args.get("pair_only") and udid:
                _say("  ! tunnel/UDID check failed: %s" % exc)
                _say("  UDID saved from the pairing: %s" % udid)
                save_state(udid=udid, paired=True)
                return 0
            raise
        if session.udid:
            if udid and udid != session.udid:
                _say("  ! the tunnel reports a different UDID than the pairing record")
            udid = session.udid
            save_state(udid=udid, paired=True)
        if not udid:
            _say("  ! could not read the target's UDID from the tunnel")
            return 2
        _say("  UDID         %s" % udid)
        if args.get("pair_only"):
            _say("  done         pairing file and UDID saved")
            return 0

        ipa = find_ipa(args.get("ipa"))
        if not ipa:
            _say("  ! no signed IPA found")
            _say("    sign on the signer first (sh bin/barisign sign), or pass --ipa FILE")
            return 2
        await asyncio.wait_for(install(session, ipa, RECORD_PATH), 900)
        _say("")
        _say("  next         on the target: Settings > General > VPN & Device Management")
        _say("               trust the developer, then open the app")
        return 0
    finally:
        if session is not None:
            await session.close()


def main(argv):
    if "--help" in argv or "-h" in argv:
        _say("sh bin/barisign pair                 pair the target and install the newest -signed.ipa")
        _say("sh bin/barisign pair --ipa FILE      use a specific signed IPA")
        _say("sh bin/barisign pair --pair-only     pair only; save the UDID and pairing file")
        _say("sh bin/barisign pair --udid UDID     use an already paired target")
        _say("sh bin/barisign pair --import FILE   use a pairing file from another host")
        _say("sh bin/barisign pair --host IP          use this target address (port is scanned)")
        _say("sh bin/barisign pair --raw-mdns     force raw advertisement (default on a-Shell)")
        _say("sh bin/barisign pair --target-ip IP  also send unicast mDNS to the target")
        _say("sh bin/barisign pair --timeout N     give up if the target never pairs")
        _say("sh bin/barisign pair --check         verify the pure engine imports")
        _say("sh bin/barisign pair --setup         verify the engine (no download needed)")
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
        "raw": "--raw-mdns" in argv,
        "timeout": int(value("--timeout", "0") or 0) or None,
        "pair_only": "--pair-only" in argv,
        "repair": "--repair" in argv,
        "debug": "--debug" in argv,
    }
    if args["host"] and not args["port"]:
        # The device's RPPairing service listens on 49152 (SideStore/LocalDevVPN
        # documents the same port); allow --port when it differs.
        args["port"] = 49152
    if "--check" in argv:
        return check()
    if "--setup" in argv or "--ensure" in argv:
        return check()
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        _say("")
        return 130
    except Exception as exc:                                    # noqa: BLE001
        _say("  ! %s" % exc)
        if args["debug"]:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
