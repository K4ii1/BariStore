#!/usr/bin/env python3
# =============================================================================
#  BariSign — Bonjour capability check for a-Shell (MIT)
#
#  Run on the signer:
#      python3 poc/bonjour_check.py
#      python3 poc/bonjour_check.py --target 192.168.1.23
#
#  It answers one question: can a-Shell advertise
#  `_remotepairing-pairable-host._tcp` at all?
#
#    * DNS-SD registration is the supported path.  iOS checks the app's
#      NSBonjourServices allowlist; `-65555` (NoAuth) means the type is not
#      listed and no Python code can add it.
#    * Raw multicast is the only code-only fallback.  iOS may block it without
#      the multicast entitlement; the probe reports bind/join/send/receive.
#
#  This changes nothing; it only prints what the device allows.
# =============================================================================

import ctypes
import select
import socket
import struct
import sys
import time

from ashell_bonjour import SERVICE_TYPE, _load_dnssd, _txt_record, REPLY, _kDNSServiceErr

TEST_TYPES = (
    "_barisign-check._tcp",
    "_http._tcp",
    SERVICE_TYPE,
)


def register_once(library, service_type):
    library.DNSServiceRegister.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_uint16, ctypes.c_uint16, ctypes.c_char_p, REPLY, ctypes.c_void_p]
    library.DNSServiceRegister.restype = ctypes.c_int32
    library.DNSServiceRefDeallocate.argtypes = [ctypes.c_void_p]
    ref = ctypes.c_void_p()
    errors = {}

    def callback(_ref, _flags, error, _name, _type, _domain, _context):
        errors["async"] = error

    cb = REPLY(callback)
    txt = _txt_record({"name": "BariSign", "identifier": "CHECK"})
    error = library.DNSServiceRegister(
        ctypes.byref(ref), 0, 0, b"BariSignCheck", service_type.encode(),
        None, None, socket.htons(49152), len(txt), txt, cb, None)
    if ref:
        try:
            library.DNSServiceRefDeallocate(ref)
        except Exception:                                       # noqa: BLE001
            pass
    return error, errors.get("async", 0)


def raw_multicast():
    print("\nraw mDNS / multicast")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bound = True
    try:
        sock.bind(("", 5353))
        print("  bind 5353      ok")
    except OSError as exc:
        print("  bind 5353      FAILED: %s" % exc)
        bound = False
    group = socket.inet_aton("224.0.0.251")
    if bound:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            group + socket.inet_aton("0.0.0.0"))
            print("  join group     ok")
        except OSError as exc:
            print("  join group     FAILED: %s" % exc)
    query = (struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
             + b"\x0e_remotepairing\x04_tcp\x05local\x00"
             + struct.pack(">HH", 12, 1))
    sender = sock
    if not bound:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sender.sendto(query, ("224.0.0.251", 5353))
        print("  multicast send ok")
    except OSError as exc:
        print("  multicast send FAILED: %s" % exc)
    if not bound:
        sender.close()
        sock.close()
        print("  received       not tested (could not bind 5353)")
        return
    sock.setblocking(False)
    deadline = time.time() + 2
    seen = False
    while time.time() < deadline:
        ready, _, _ = select.select([sock], [], [], 0.2)
        if not ready:
            continue
        try:
            data, address = sock.recvfrom(9000)
        except OSError:
            continue
        print("  received       %d bytes from %s" % (len(data), address[0]))
        seen = True
        break
    if not seen:
        print("  received       nothing in 2 s (raw multicast may be blocked)")
    sock.close()


def main(argv):
    print("Bonjour capability check (a-Shell)\n")
    try:
        library = _load_dnssd()
        print("DNS-SD library    ok")
    except Exception as exc:                                    # noqa: BLE001
        print("DNS-SD library    FAILED: %s" % exc)
        return 1
    results = {}
    for service_type in TEST_TYPES:
        error, async_error = register_once(library, service_type)
        results[service_type] = error or async_error
        text = _kDNSServiceErr.get(error or async_error, "error %d" % (error or async_error))
        print("  %-38s %s" % (service_type, "ok" if not (error or async_error) else text))
    print()
    if all(results.values()):
        print("CONCLUSION: a-Shell cannot register any Bonjour type (no allowlist).")
        print("The Settings > Paired Macs discovery path cannot run from a-Shell.")
    elif results.get(SERVICE_TYPE):
        print("CONCLUSION: Bonjour works, but _remotepairing-pairable-host._tcp is")
        print("not in a-Shell's NSBonjourServices allowlist.")
    else:
        print("CONCLUSION: the pairing service type is allowed; check the TXT records.")
    raw_multicast()
    print("\nIf raw multicast send/receive worked, a raw mDNS fallback is worth testing.")
    print("If it did not, the pairing host needs an app with the right Info.plist.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
