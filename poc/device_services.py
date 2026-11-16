#!/usr/bin/env python3
# =============================================================================
#  BariSign — device services over the pairing tunnel (MIT)
#
#  After RSD gives us the service port map, three services are enough:
#
#    * installation_proxy  — Install a staged .ipa as a developer package
#    * com.apple.afc       — upload the .ipa to /PublicStaging
#    * house_arrest        — write the pairing file into AltStore/SideStore
#
#  They speak the classic lockdown framing: a 4-byte big-endian length followed
#  by an XML plist.  Each service starts with an RSDCheckin exchange.  AFC then
#  switches to its own 40-byte-header binary protocol on the same connection.
#
#  Reference (read, not copied): jkcoxson/idevice services/{afc,house_arrest,
#  installation_proxy}.rs (MIT); formats are Apple's public wire formats.
#
#  UNTESTED ON A DEVICE.  Header/framing round-trips are unit-tested on Linux.
# =============================================================================

import os
import plistlib
import struct
import uuid

AFC_MAGIC = b"CFA6LPAA"
AFC_HEADER = 40

OP_STATUS = 0x01
OP_DATA = 0x02
OP_REMOVE_PATH = 0x08
OP_MAKE_DIR = 0x09
OP_FILE_OPEN = 0x0D
OP_FILE_OPEN_RES = 0x0E
OP_WRITE = 0x10
OP_FILE_CLOSE = 0x14
OP_REMOVE_PATH_AND_CONTENTS = 0x22

FOPEN_WRONLY = 0x03

INSTALL_SERVICE = "com.apple.mobile.installation_proxy.shim.remote"
AFC_SERVICE = "com.apple.afc.shim.remote"
HOUSE_ARREST_SERVICE = "com.apple.mobile.house_arrest.shim.remote"


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
        except Exception as exc:                                # noqa: BLE001
            raise DeviceServiceError("cannot decode plist: %s" % exc)

    async def send_receive(self, value):
        await self.send_plist(value)
        return await self.recv_plist()

    async def close(self):
        try:
            self.writer.close()
        except Exception:                                       # noqa: BLE001
            pass
        try:
            await self.writer.wait_closed()
        except Exception:                                       # noqa: BLE001
            pass


async def open_service(stack, host, port):
    """Connect through the tunnel and complete the RSDCheckin exchange."""
    connection = await stack.connect(host, port)
    service = LockdownConnection(connection, connection)
    response = await service.send_receive({
        "Label": "BariSign",
        "ProtocolVersion": "2",
        "Request": "RSDCheckin",
    })
    if response.get("Request") != "RSDCheckin":
        raise DeviceServiceError("unexpected RSDCheckin reply: %r" % (response,))
    started = await service.recv_plist()
    if started.get("Request") != "StartService":
        raise DeviceServiceError("unexpected StartService reply: %r" % (started,))
    if started.get("Error"):
        raise DeviceServiceError("the device refused the service: %s" % started["Error"])
    return service


class Afc:
    """The small AFC subset needed for staging an IPA and writing one file."""

    def __init__(self, connection):
        self.connection = connection
        self.packet = 0

    async def _request(self, op, payload=b"", this_length=0):
        total = AFC_HEADER + len(payload)
        header = AFC_MAGIC + struct.pack("<QQQQ", total, this_length or total,
                                          self.packet, op)
        self.packet += 1
        self.connection.writer.write(header + payload)
        await self.connection.writer.drain()
        response = await self.connection.reader.readexactly(AFC_HEADER)
        if response[:8] != AFC_MAGIC:
            raise DeviceServiceError("bad AFC magic in reply")
        entire, this, packet, rop = struct.unpack("<QQQQ", response[8:40])
        if entire < AFC_HEADER or entire > 64 * 1024 * 1024:
            raise DeviceServiceError("bad AFC reply length %d" % entire)
        body = await self.connection.reader.readexactly(entire - AFC_HEADER) if entire > AFC_HEADER else b""
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
                pass                                      # already exists

    async def remove(self, path):
        try:
            await self._request(OP_REMOVE_PATH, path.encode() + b"\x00")
        except DeviceServiceError:
            pass

    async def fopen(self, path, mode=FOPEN_WRONLY):
        body = await self._request(OP_FILE_OPEN, struct.pack("<Q", mode) + path.encode() + b"\x00")
        if len(body) < 8:
            raise DeviceServiceError("AFC fopen returned no handle")
        return struct.unpack("<Q", body[:8])[0]

    async def fwrite(self, handle, data):
        # AFC streaming write: this_length covers the header + handle only.
        await self._request(OP_WRITE, struct.pack("<Q", handle) + data,
                            this_length=AFC_HEADER + 8)

    async def fclose(self, handle):
        await self._request(OP_FILE_CLOSE, struct.pack("<Q", handle))

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


async def open_afc(stack, host, port):
    connection = await open_service(stack, host, port)
    return Afc(connection), connection


async def vend_container(stack, host, port, bundle_id, documents_only=False):
    connection = await open_service(stack, host, port)
    command = "VendDocuments" if documents_only else "VendContainer"
    response = await connection.send_receive({"Command": command, "Identifier": bundle_id})
    if response.get("Error"):
        await connection.close()
        raise DeviceServiceError("cannot open the container of %s: %s"
                                 % (bundle_id, response["Error"]))
    return Afc(connection), connection


async def install_ipa(stack, host, install_port, afc_port, ipa_path, progress=None, log=None):
    """Upload the IPA to /PublicStaging (AFC) and install it as a developer package."""
    remote = "/PublicStaging/barisign-%s.ipa" % uuid.uuid4().hex[:12]
    afc_connection = await open_service(stack, host, afc_port)
    afc = Afc(afc_connection)
    try:
        await afc.makedirs("/PublicStaging")
        if log:
            log("uploading %s" % os.path.basename(ipa_path))
        await afc.upload_file(remote, ipa_path, progress=progress)
        if log:
            log("uploaded %d bytes" % os.path.getsize(ipa_path))
    finally:
        await afc_connection.close()

    service = await open_service(stack, host, install_port)
    try:
        await service.send_plist({
            "Command": "Install",
            "ClientOptions": {"PackageType": "Developer"},
            "PackagePath": remote,
        })
        while True:
            response = await service.recv_plist()
            if isinstance(response, dict) and response.get("Error"):
                raise DeviceServiceError("install failed: %s" % response["Error"])
            status = response.get("Status") if isinstance(response, dict) else None
            if status == "Complete":
                return True
            if status and log and response.get("PercentComplete") is not None:
                log("%s %s%%" % (status, response["PercentComplete"]))
    finally:
        try:
            remover = await open_service(stack, host, afc_port)
            try:
                await Afc(remover).remove(remote)
            finally:
                await remover.close()
        except Exception:                                   # noqa: BLE001
            pass
        await service.close()
