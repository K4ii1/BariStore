"""Test helper: a TLS 1.2 PSK echo server built on Python's OpenSSL-backed ssl.

Python 3.13+ exposes set_psk_server_callback(); that is what makes this a real
interop test for the pure-Python client in poc/tls_psk.py.
"""
import asyncio
import ssl
import sys


async def main(port, psk_hex, cipher="PSK-AES256-CBC-SHA384"):
    psk = bytes.fromhex(psk_hex)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(cipher)
    ctx.set_psk_server_callback(lambda identity: psk)

    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as exc:  # noqa: BLE001
            print("server error: %r" % (exc,), file=sys.stderr)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", int(port), ssl=ctx)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "PSK-AES256-CBC-SHA384"))
