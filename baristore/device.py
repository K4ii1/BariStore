#!/usr/bin/env python3
# =============================================================================
#  BariStore — Device Services over the Pairing Tunnel (MIT)
#
#  Services implemented over the userspace TCP/IPv6 + RSD tunnel:
#    * lockdownd & AMFI  — Developer Mode status, reveal toggle, enable & reboot
#    * AFC               — Upload IPAs to /PublicStaging and manage container files
#    * house_arrest      — Inject pairing files & prefs into SideStore/AltStore/LC/StikDebug
#    * installation_proxy — Install, Upgrade, Uninstall, and Lookup installed apps
#    * debug_proxy       — StikDebug-style JIT Enabler via GDB Remote Serial Protocol
# =============================================================================

import asyncio
import os
import plistlib
import struct
import uuid
import zipfile

from . import remote_xpc, signer, storage

AFC_MAGIC = b"CFA6LPAA"
AFC_HEADER = 40

OP_STATUS = 0x01
OP_DATA = 0x02
OP_REMOVE_PATH = 0x08
OP_MAKE_DIR = 0x09
OP_FILE_OPEN = 0x0D
OP_FILE_OPEN_RES = 0x0E
OP_READ = 0x0F
OP_WRITE = 0x10
OP_FILE_CLOSE = 0x14
OP_REMOVE_PATH_AND_CONTENTS = 0x22

FOPEN_RDONLY = 0x01
FOPEN_WRONLY = 0x03

INSTALL_SERVICE = "com.apple.mobile.installation_proxy.shim.remote"
AFC_SERVICE = "com.apple.afc.shim.remote"
HOUSE_ARREST_SERVICE = "com.apple.mobile.house_arrest.shim.remote"
DEBUG_PROXY_SERVICE = "com.apple.internal.dt.remote.debugproxy"

LOCKDOWN_NAMES = (
    "com.apple.mobile.lockdown.remote.trusted",
    "com.apple.mobile.lockdown",
)
AMFI_NAMES = (
    "com.apple.amfi.lockdown.shim.remote",
    "com.apple.amfi.lockdown",
)
AMFI_DOMAIN = "com.apple.security.mac.amfi"
STATUS_KEY = "DeveloperModeStatus"
DEVMODE_SHOW = 0
DEVMODE_TURN_ON = 1


class DeviceServiceError(Exception):
    pass


class LockdownConnection:
    """Length-prefixed plist service connection (classic lockdown framing)."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def send_plist(self, value):
        payload = plistlib.dumps(value, fmt=plistlib.FMT_XML)
        self.writer.write(struct.pack(">I", len(payload)) + payload)
        await self.writer.drain()

    async def recv_plist(self):
        header = await self.reader.readexactly(4)
        length = struct.unpack(">I", header)[0]
        if length <= 0 or length > 64 * 1024 * 1024:
            raise DeviceServiceError("invalid plist length %d" % length)
        payload = await self.reader.readexactly(length)
        try:
            return plistlib.loads(payload)
        except Exception as exc:
            raise DeviceServiceError("cannot decode plist: %s" % exc)

    async def send_receive(self, value):
        await self.send_plist(value)
        return await self.recv_plist()

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


async def open_service(stack, host, port):
    """Connect through the tunnel and complete the RSDCheckin exchange."""
    connection = await stack.connect(host, port)
    service = LockdownConnection(connection, connection)
    response = await service.send_receive(
        {
            "Label": "BariStore",
            "ProtocolVersion": "2",
            "Request": "RSDCheckin",
        }
    )
    if response.get("Request") != "RSDCheckin":
        raise DeviceServiceError("unexpected RSDCheckin reply: %r" % (response,))
    started = await service.recv_plist()
    if started.get("Request") != "StartService":
        raise DeviceServiceError("unexpected StartService reply: %r" % (started,))
    if started.get("Error"):
        raise DeviceServiceError("the device refused the service: %s" % started["Error"])
    return service


# --- Developer Mode (lockdownd + AMFI) --------------------------------------

async def devmode_status(session):
    """Return True if Developer Mode is enabled, False if disabled, None if unreadable."""
    port = remote_xpc.service_port(session.services, *LOCKDOWN_NAMES)
    service = await open_service(session.stack, session.address, port)
    try:
        response = await service.send_receive(
            {
                "Label": "BariStore",
                "Request": "GetValue",
                "Key": STATUS_KEY,
                "Domain": AMFI_DOMAIN,
            }
        )
    finally:
        await service.close()
    if "Error" in response:
        return None
    value = response.get("Value")
    return bool(value) if isinstance(value, bool) else None


async def _amfi_action(session, action):
    port = remote_xpc.service_port(session.services, *AMFI_NAMES)
    service = await open_service(session.stack, session.address, port)
    try:
        response = await service.send_receive({"action": action})
    except Exception as exc:
        return False, True, "hung up: %s" % exc
    finally:
        await service.close()
    if response.get("success"):
        return True, False, ""
    error = response.get("Error") or response.get("error") or "refused"
    return False, False, str(error)


async def devmode_show_switch(session):
    """Reveal the Developer Mode toggle in Settings > Privacy & Security (no reboot)."""
    ok, hung_up, text = await _amfi_action(session, DEVMODE_SHOW)
    if ok or hung_up:
        return True
    raise DeviceServiceError("Could not reveal Developer Mode toggle: %s" % text)


async def devmode_turn_on(session):
    """Enable Developer Mode immediately (triggers device restart unless passcode blocks it)."""
    ok, hung_up, text = await _amfi_action(session, DEVMODE_TURN_ON)
    if ok or hung_up:
        return True
    if "passcode" in text.lower():
        raise DeviceServiceError("passcode-set")
    raise DeviceServiceError("Could not turn Developer Mode on: %s" % text)


# --- AFC & house_arrest -----------------------------------------------------

class Afc:
    """AFC client for staging IPAs and writing container files."""

    def __init__(self, connection):
        self.connection = connection
        self.packet = 0

    async def _request(self, op, payload=b"", this_length=0):
        total = AFC_HEADER + len(payload)
        header = AFC_MAGIC + struct.pack(
            "<QQQQ", total, this_length or total, self.packet, op
        )
        self.packet += 1
        self.connection.writer.write(header + payload)
        await self.connection.writer.drain()
        response = await self.connection.reader.readexactly(AFC_HEADER)
        if response[:8] != AFC_MAGIC:
            raise DeviceServiceError("bad AFC magic in reply")
        entire, _this, _packet, rop = struct.unpack("<QQQQ", response[8:40])
        if entire < AFC_HEADER or entire > 64 * 1024 * 1024:
            raise DeviceServiceError("bad AFC reply length %d" % entire)
        body = (
            await self.connection.reader.readexactly(entire - AFC_HEADER)
            if entire > AFC_HEADER
            else b""
        )
        if rop == OP_STATUS:
            if len(body) >= 8:
                status = struct.unpack("<Q", body[:8])[0]
                if status:
                    raise DeviceServiceError("AFC status %d for operation 0x%X" % (status, op))
            return b""
        if rop in (OP_DATA, OP_FILE_OPEN_RES):
            return body
        raise DeviceServiceError("unexpected AFC reply opcode 0x%X" % rop)

    async def makedirs(self, path):
        current = ""
        for part in path.strip("/").split("/"):
            if not part:
                continue
            current += "/" + part
            try:
                await self._request(OP_MAKE_DIR, current.encode() + b"\x00")
            except DeviceServiceError:
                pass

    async def remove(self, path):
        try:
            await self._request(OP_REMOVE_PATH, path.encode() + b"\x00")
        except DeviceServiceError:
            pass

    async def fopen(self, path, mode=FOPEN_WRONLY):
        body = await self._request(
            OP_FILE_OPEN, struct.pack("<Q", mode) + path.encode() + b"\x00"
        )
        if len(body) < 8:
            raise DeviceServiceError("AFC fopen returned no handle")
        return struct.unpack("<Q", body[:8])[0]

    async def fwrite(self, handle, data):
        await self._request(
            OP_WRITE, struct.pack("<Q", handle) + data, this_length=AFC_HEADER + 8
        )

    async def fclose(self, handle):
        await self._request(OP_FILE_CLOSE, struct.pack("<Q", handle))

    async def fread(self, handle, size):
        return await self._request(OP_READ, struct.pack("<QQ", handle, size))

    async def download(self, path, chunk=256 * 1024, limit=1024 * 1024):
        try:
            handle = await self.fopen(path, mode=FOPEN_RDONLY)
        except DeviceServiceError:
            return b""
        out = bytearray()
        try:
            while len(out) < limit:
                block = await self.fread(handle, min(chunk, limit - len(out)))
                if not block:
                    break
                out += block
                if len(block) < chunk:
                    break
        except DeviceServiceError:
            return b""
        finally:
            try:
                await self.fclose(handle)
            except DeviceServiceError:
                pass
        return bytes(out)

    async def upload(self, path, data, chunk=128 * 1024, progress=None):
        handle = await self.fopen(path)
        try:
            for offset in range(0, len(data), chunk):
                await self.fwrite(handle, data[offset:offset + chunk])
                if progress is not None:
                    progress(min(offset + chunk, len(data)), len(data))
        finally:
            await self.fclose(handle)

    async def upload_file(self, path, local_path, chunk=128 * 1024, progress=None):
        size = os.path.getsize(local_path)
        handle = await self.fopen(path)
        sent = 0
        try:
            with open(local_path, "rb") as handle_file:
                while True:
                    block = handle_file.read(chunk)
                    if not block:
                        break
                    await self.fwrite(handle, block)
                    sent += len(block)
                    if progress is not None:
                        progress(sent, size)
        finally:
            await self.fclose(handle)


async def vend_container(stack, host, port, bundle_id, documents_only=False):
    connection = await open_service(stack, host, port)
    command = "VendDocuments" if documents_only else "VendContainer"
    response = await connection.send_receive({"Command": command, "Identifier": bundle_id})
    if response.get("Error"):
        await connection.close()
        raise DeviceServiceError(
            "Cannot open container of %s: %s" % (bundle_id, response["Error"])
        )
    return Afc(connection), connection


# --- Pairing File Injection for Store / Container / JIT Apps ----------------

def pairing_target(bundle_id):
    """Return (documents_only, [relative_paths], prefs_path_or_None) for store/JIT apps."""
    base = bundle_id or ""
    low = base.lower()
    if ".beta" in low and "altstore" in low:
        return None
    if base == "com.rileytestut.AltStore" or base.startswith("com.rileytestut.AltStore.") or "altstore" in low:
        return True, ("ALTPairingFile.plist",), None
    if base == "com.SideStore.SideStore" or base.startswith("com.SideStore.SideStore.") or "sidestore" in low:
        return (
            True,
            ("ALTPairingFile.mobiledevicepairing", "PairingFile_RemoteRP.plist"),
            "Library/Preferences/%s.plist" % base,
        )
    if base == "com.kdt.livecontainer" or base.startswith("com.kdt.livecontainer.") or "livecontainer" in low:
        return (
            False,
            (
                "Documents/ALTPairingFile.mobiledevicepairing",
                "Documents/PairingFile_RemoteRP.plist",
                "SideStore/Documents/ALTPairingFile.mobiledevicepairing",
                "SideStore/Documents/PairingFile_RemoteRP.plist",
            ),
            "Documents/SideStore/Library/Preferences/com.SideStore.SideStore.plist",
        )
    if "stikdebug" in low or base.startswith("com.stik."):
        return (
            True,
            ("pairingFile.plist", "ALTPairingFile.mobiledevicepairing", "PairingFile_RemoteRP.plist"),
            None,
        )
    return None


def merge_sidestored_prefs(existing):
    if existing:
        try:
            prefs = plistlib.loads(existing)
        except Exception:
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


async def write_pairing_file_to_app(session, bundle_id):
    """Write the normalized RPPairing file into an installed store/container app."""
    target = pairing_target(bundle_id)
    if target is None:
        # Generic fallback when user explicitly requests pairing injection for any app:
        target = (
            True,
            ("ALTPairingFile.mobiledevicepairing", "PairingFile_RemoteRP.plist", "ALTPairingFile.plist"),
            None,
        )
    documents_only, names, prefs_name = target
    data = storage.export_pairing_bytes()
    port = remote_xpc.service_port(session.services, HOUSE_ARREST_SERVICE)
    afc, connection = await vend_container(
        session.stack, session.address, port, bundle_id, documents_only=documents_only
    )
    try:
        for name in names:
            directory = os.path.dirname(name)
            if directory:
                await afc.makedirs("/" + directory)
            await afc.upload("/" + name, data)
    finally:
        await connection.close()

    if prefs_name is not None:
        try:
            whole, whole_conn = await vend_container(
                session.stack, session.address, port, bundle_id, documents_only=False
            )
            try:
                directory = os.path.dirname(prefs_name)
                if directory:
                    await whole.makedirs("/" + directory)
                merged = merge_sidestored_prefs(await whole.download("/" + prefs_name))
                if merged is not None:
                    await whole.upload("/" + prefs_name, merged)
            finally:
                await whole_conn.close()
        except Exception:
            pass
    return True


# --- installation_proxy (Install, Uninstall, Lookup) ------------------------

def ipa_bundle_id(ipa):
    try:
        with zipfile.ZipFile(ipa) as archive:
            names = [
                name
                for name in archive.namelist()
                if name.startswith("Payload/")
                and name.endswith(".app/Info.plist")
                and name.count("/") == 2
            ]
            if not names:
                return ""
            info = plistlib.loads(archive.read(names[0]))
            return info.get("CFBundleIdentifier") or ""
    except Exception:
        return ""


def preflight_ipa(ipa, udid):
    try:
        with zipfile.ZipFile(ipa) as archive:
            names = [
                name
                for name in archive.namelist()
                if name.startswith("Payload/")
                and name.endswith(".app/embedded.mobileprovision")
                and name.count("/") == 2
            ]
            if not names:
                raise DeviceServiceError("The signed IPA has no embedded provisioning profile.")
            blob = archive.read(names[0])
    except zipfile.BadZipFile:
        raise DeviceServiceError("Invalid or corrupt IPA archive: %s" % ipa)
    profile = signer.parse_mobileprovision_blob(blob)
    problems = signer.install_preflight(profile, udid)
    if problems:
        raise DeviceServiceError("; ".join(problems))


async def install_ipa(session, ipa_path, progress=None, log=None, auto_inject_pairing=True):
    """Upload a signed IPA to /PublicStaging and install it via installation_proxy."""
    install_port = remote_xpc.service_port(session.services, INSTALL_SERVICE)
    afc_port = remote_xpc.service_port(session.services, AFC_SERVICE)
    bundle_id = ipa_bundle_id(ipa_path)
    preflight_ipa(ipa_path, session.udid)

    remote = "/PublicStaging/baristore-%s.ipa" % uuid.uuid4().hex[:12]
    afc_connection = await open_service(session.stack, session.address, afc_port)
    afc = Afc(afc_connection)
    try:
        await afc.makedirs("/PublicStaging")
        if log:
            log("Uploading %s to device…" % os.path.basename(ipa_path))
        await afc.upload_file(remote, ipa_path, progress=progress)
    finally:
        await afc_connection.close()

    service = await open_service(session.stack, session.address, install_port)
    try:
        await service.send_plist(
            {
                "Command": "Install",
                "ClientOptions": {"PackageType": "Developer"},
                "PackagePath": remote,
            }
        )
        while True:
            response = await service.recv_plist()
            if isinstance(response, dict) and response.get("Error"):
                desc = response.get("ErrorDescription") or response.get("Error")
                raise DeviceServiceError("Install failed: %s" % desc)
            status = response.get("Status") if isinstance(response, dict) else None
            if status == "Complete":
                break
            if status and log and response.get("PercentComplete") is not None:
                log("%s (%s%%)" % (status, response["PercentComplete"]))
    finally:
        try:
            remover = await open_service(session.stack, session.address, afc_port)
            try:
                await Afc(remover).remove(remote)
            finally:
                await remover.close()
        except Exception:
            pass
        await service.close()

    if auto_inject_pairing and bundle_id and pairing_target(bundle_id) is not None:
        if log:
            log("Injecting pairing file into %s…" % bundle_id)
        try:
            await write_pairing_file_to_app(session, bundle_id)
        except Exception as exc:
            if log:
                log("Pairing file note: %s" % exc)

    return bundle_id


async def uninstall_app(session, bundle_id):
    """Uninstall an application by bundle identifier via installation_proxy."""
    install_port = remote_xpc.service_port(session.services, INSTALL_SERVICE)
    service = await open_service(session.stack, session.address, install_port)
    try:
        await service.send_plist(
            {
                "Command": "Uninstall",
                "ApplicationIdentifier": bundle_id,
                "ClientOptions": {},
            }
        )
        while True:
            response = await service.recv_plist()
            if isinstance(response, dict) and response.get("Error"):
                desc = response.get("ErrorDescription") or response.get("Error")
                raise DeviceServiceError("Uninstall failed: %s" % desc)
            if isinstance(response, dict) and response.get("Status") == "Complete":
                return True
    finally:
        await service.close()


async def lookup_installed_apps(session, bundle_ids=None):
    """Return a dict of user-installed apps keyed by bundle identifier."""
    install_port = remote_xpc.service_port(session.services, INSTALL_SERVICE)
    service = await open_service(session.stack, session.address, install_port)
    try:
        opts = {"ApplicationType": "User"}
        if bundle_ids:
            opts["BundleIDs"] = list(bundle_ids)
        response = await service.send_receive(
            {
                "Command": "Lookup",
                "ClientOptions": opts,
            }
        )
        result = response.get("LookupResult")
        return result if isinstance(result, dict) else {}
    finally:
        await service.close()


# --- StikDebug-style JIT Enabler (GDB Remote Serial Protocol) ---------------

def _gdb_checksum(text):
    return "%02x" % (sum(text.encode("utf-8")) & 0xFF)


def _gdb_packet(command_str):
    return ("$%s#%s" % (command_str, _gdb_checksum(command_str))).encode("utf-8")


async def _gdb_read_packet(reader, noack=True, timeout=8.0):
    if not noack:
        ch = await asyncio.wait_for(reader.readexactly(1), timeout)
        while ch in (b"+", b"-"):
            if ch == b"+":
                break
            ch = await asyncio.wait_for(reader.readexactly(1), timeout)
    while True:
        ch = await asyncio.wait_for(reader.readexactly(1), timeout)
        if ch == b"$":
            break
    buf = bytearray()
    while True:
        ch = await asyncio.wait_for(reader.readexactly(1), timeout)
        if ch == b"#":
            break
        buf += ch
    await asyncio.wait_for(reader.readexactly(2), timeout)  # checksum
    return buf.decode("utf-8", "replace")


async def enable_jit(session, bundle_id):
    """Enable JIT on a sideloaded app over `com.apple.internal.dt.remote.debugproxy`.

    Works like StikDebug:
      1. Looks up the app's executable name and path via `installation_proxy`.
      2. Connects to `com.apple.internal.dt.remote.debugproxy` on the RSD tunnel.
      3. Switches to `QStartNoAckMode`.
      4. Attaches to the running process with `vAttachName;<hex_exec>` (or launches
         and attaches via the GDB `A` packet if not yet running).
      5. Sends `D` (detach), leaving `CS_DEBUGGED` (JIT) active for the app.
    """
    apps = await lookup_installed_apps(session, [bundle_id])
    app_info = apps.get(bundle_id)
    if not app_info:
        # Try matching by prefix if team ID suffix differs
        all_apps = await lookup_installed_apps(session)
        for bid, info in all_apps.items():
            if bid == bundle_id or bid.startswith(bundle_id + "."):
                app_info = info
                bundle_id = bid
                break
    if not app_info:
        raise DeviceServiceError(
            "App %s is not installed on this device." % bundle_id
        )

    executable = app_info.get("CFBundleExecutable") or ""
    bundle_path = app_info.get("Path") or ""
    if not executable:
        raise DeviceServiceError("Could not determine executable name for %s" % bundle_id)

    debug_port = remote_xpc.service_port(session.services, DEBUG_PROXY_SERVICE)
    conn = await session.stack.connect(session.address, debug_port, timeout=10)
    try:
        conn.write(b"++")
        await conn.drain()
        conn.write(_gdb_packet("QStartNoAckMode"))
        await conn.drain()
        ack_resp = await _gdb_read_packet(conn, noack=False, timeout=5.0)
        noack = ack_resp == "OK"

        exec_hex = executable.encode("utf-8").hex().upper()
        conn.write(_gdb_packet("vAttachName;" + exec_hex))
        await conn.drain()
        attach_resp = await _gdb_read_packet(conn, noack=noack, timeout=8.0)

        # If the process is not currently running (E response), launch via 'A' packet
        if attach_resp.startswith("E") and bundle_path:
            full_exec = bundle_path.rstrip("/") + "/" + executable
            path_hex = full_exec.encode("utf-8").hex().upper()
            a_cmd = "A%d,0,%s" % (len(path_hex), path_hex)
            conn.write(_gdb_packet(a_cmd))
            await conn.drain()
            a_resp = await _gdb_read_packet(conn, noack=noack, timeout=8.0)
            if a_resp == "OK":
                conn.write(_gdb_packet("qLaunchSuccess"))
                await conn.drain()
                launch_resp = await _gdb_read_packet(conn, noack=noack, timeout=8.0)
                if launch_resp == "OK":
                    attach_resp = "T00"

        if attach_resp.startswith("E"):
            raise DeviceServiceError(
                "Could not attach to %s (%s). Open the app first so it is running in the background, then tap Enable JIT."
                % (executable, attach_resp)
            )

        # Detach cleanly so the app continues running with CS_DEBUGGED (JIT) enabled
        conn.write(_gdb_packet("D"))
        await conn.drain()
        try:
            await _gdb_read_packet(conn, noack=noack, timeout=3.0)
        except Exception:
            pass
        return {
            "bundle_id": bundle_id,
            "executable": executable,
            "status": "JIT enabled",
        }
    finally:
        conn.close()
        await conn.wait_closed()
