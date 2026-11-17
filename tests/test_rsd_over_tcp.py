#!/usr/bin/env python3
"""RSD + AFC + installation_proxy over the pure TCP stack through Linux TUN."""
import asyncio
import datetime
import os
import plistlib
import struct
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import test_tcp6 as tun
from baristore import device, remote_xpc, tcp6


async def read_plist(reader):
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    return plistlib.loads(await reader.readexactly(length))


async def send_plist(writer, value):
    payload = plistlib.dumps(value, fmt=plistlib.FMT_XML)
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


AFC_PORT = [0]
INSTALL_PORT = [0]
UPLOADED = []
COMMAND = []


async def rsd_handler(reader, writer):
    assert await reader.readexactly(len(remote_xpc.HTTP2_MAGIC)) == remote_xpc.HTTP2_MAGIC
    for _ in range(7):
        header = await reader.readexactly(9)
        length = int.from_bytes(header[:3], "big")
        if length:
            await reader.readexactly(length)
    writer.write(remote_xpc.Frame(remote_xpc.TYPE_SETTINGS, 0, 0, b"").build())
    header = await reader.readexactly(9)
    length = int.from_bytes(header[:3], "big")
    await reader.readexactly(length)
    services = {
        "com.apple.afc.shim.remote": {"Port": str(AFC_PORT[0])},
        "com.apple.mobile.installation_proxy.shim.remote": {"Port": str(INSTALL_PORT[0])},
        "com.apple.mobile.house_arrest.shim.remote": {"Port": str(AFC_PORT[0])},
    }
    peer = {
        "Services": services,
        "Properties": {"UniqueDeviceID": "d" * 40, "ProductType": "iPhone17,1"},
    }
    payload = remote_xpc.encode_wrapper(peer, message_id=1, flags=0x0001)
    writer.write(remote_xpc.Frame(remote_xpc.TYPE_DATA, 0, 1, payload).build())
    await writer.drain()
    await asyncio.sleep(1)
    writer.close()


async def afc_handler(reader, writer):
    await send_plist(writer, {"Request": "RSDCheckin"})
    await read_plist(reader)
    await send_plist(writer, {"Request": "StartService"})
    data = bytearray()
    while True:
        try:
            header = await reader.readexactly(40)
        except (asyncio.IncompleteReadError, ConnectionError):
            return
        entire = struct.unpack("<Q", header[8:16])[0]
        op = struct.unpack("<Q", header[32:40])[0]
        body = await reader.readexactly(entire - 40) if entire > 40 else b""
        if op == device.OP_FILE_OPEN:
            body_out = struct.pack("<Q", 5)
        elif op == device.OP_WRITE:
            data += body[8:]
            body_out = b""
        else:
            body_out = b""
        writer.write(
            device.AFC_MAGIC
            + struct.pack(
                "<QQQQ", 40 + len(body_out), 40 + len(body_out), 0, device.OP_DATA
            )
            + body_out
        )
        await writer.drain()
        if op == device.OP_FILE_CLOSE:
            UPLOADED.append(bytes(data))
            data = bytearray()


async def install_handler(reader, writer):
    await send_plist(writer, {"Request": "RSDCheckin"})
    await read_plist(reader)
    await send_plist(writer, {"Request": "StartService"})
    command = await read_plist(reader)
    COMMAND.append(command)
    await send_plist(writer, {"Status": "CreatingStagingDirectory", "PercentComplete": 10})
    await send_plist(writer, {"Status": "Installing", "PercentComplete": 90})
    await send_plist(writer, {"Status": "Complete"})


class _Sess:
    def __init__(self, stack, address, services, udid):
        self.stack = stack
        self.address = address
        self.services = services
        self.udid = udid


async def main():
    fd = tun.setup()
    loop = asyncio.get_running_loop()
    link = tun.TunLink(fd, loop)
    rsd = await asyncio.start_server(rsd_handler, tun.KERNEL_IP, 0)
    afc = await asyncio.start_server(afc_handler, tun.KERNEL_IP, 0)
    install = await asyncio.start_server(install_handler, tun.KERNEL_IP, 0)
    AFC_PORT[0] = afc.sockets[0].getsockname()[1]
    INSTALL_PORT[0] = install.sockets[0].getsockname()[1]
    rsd_port = rsd.sockets[0].getsockname()[1]

    stack = tcp6.TcpStack(link, tun.STACK_IP)
    await stack.start()
    connection = await stack.connect(tun.KERNEL_IP, rsd_port)
    services, properties, client = await remote_xpc.connect_rsd(connection, connection)
    assert properties["UniqueDeviceID"] == "d" * 40
    assert remote_xpc.service_port(services, device.AFC_SERVICE) == AFC_PORT[0]

    now = datetime.datetime.now(datetime.timezone.utc)
    profile_blob = plistlib.dumps(
        {
            "ExpirationDate": now + datetime.timedelta(days=7),
            "ProvisionedDevices": ["d" * 40],
        },
        fmt=plistlib.FMT_XML,
    )
    with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as handle:
        path = handle.name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "Payload/App.app/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": "com.example.App"}, fmt=plistlib.FMT_XML),
        )
        zf.writestr("Payload/App.app/embedded.mobileprovision", profile_blob)
        zf.writestr("Payload/App.app/data.bin", bytes(range(256)) * 1100)

    expected_bytes = open(path, "rb").read()
    try:
        sess = _Sess(stack, tun.KERNEL_IP, services, "d" * 40)
        await device.install_ipa(sess, path, auto_inject_pairing=False)
    finally:
        os.unlink(path)
    assert UPLOADED and UPLOADED[0] == expected_bytes, "uploaded bytes differ"
    assert COMMAND[0]["ClientOptions"] == {"PackageType": "Developer"}
    await client.close()
    await stack.close()
    for srv in (rsd, afc, install):
        srv.close()
    await asyncio.gather(*(srv.wait_closed() for srv in (rsd, afc, install)))
    os.close(fd)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        tun.teardown()
    print("ok  RSD + AFC (300 KiB) + installation_proxy over the pure TCP stack")
