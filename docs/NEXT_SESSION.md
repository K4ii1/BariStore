# Next session — handoff (2026-11-15)

State: version **0.9.0**, pure on-device pairing/tunnel/install engine, working tree clean after
commit. Signing, the developer portal, the UDID fallback page and the self-updater are unchanged and
still work.

**Confirmed blocker (device, 2026-11-15): a-Shell cannot advertise the pairing service.**
`sh bin/barisign pair` stops at `DNSServiceRegister: -65555 (NoAuth)`. `-65555` is
`kDNSServiceErr_NoAuth`: iOS only lets an app register a Bonjour type listed in its **signed
`Info.plist` `NSBonjourServices`** allowlist. a-Shell has no `_remotepairing-pairable-host._tcp`
entry (its `Info.plist` has `NSLocalNetworkUsageDescription` but no `NSBonjourServices`), and Python
cannot edit a signed app. So the target's **Settings → Paired Macs** cannot discover BariSign when
BariSign runs inside a-Shell. This is not a protocol bug in the pure engine; the pairing host simply
never gets advertised.

The **tunnel/install half of the engine remains valid**: it needs a pairing record, not the
advertisement. If a record is already in `state/PairingFile_RemoteRP.plist` (from a host that can
advertise), `sh bin/barisign pair --udid UDID` still uses the pure engine to install.

`udid --pair` is no longer needed: `sh bin/barisign udid` pairs automatically (or falls back to the
page), and `sh bin/barisign pair` pairs by itself when no record exists.

## What changed

The `qh3`/`sslpsk`/`pymobiledevice3` route is gone. `sh bin/barisign pair` now runs a self-contained
MIT Python stack in `poc/` on top of the `cryptography` **3.4.8** that a-Shell ships:

| File | Job |
|---|---|
| `poc/pairing.py` | device-initiated pairing host: SRP-6a (3072-bit, SHA-512), TLV8, OPACK, Ed25519 identity, SipHash `authTag` |
| `poc/rpp_tunnel.py` | RPPairing control channel (pair-verify), `createListener`, TLS 1.2 PSK tunnel, CDTunnel handshake, IPv6 link |
| `poc/tls_psk.py` | TLS 1.2 PSK client, cipher suites `0x00AF` (`AES-256-CBC-SHA384`) and `0x008C` (`AES-128-CBC-SHA`) |
| `poc/tcp6.py` | minimal userspace IPv6/TCP client (handshake, ACKs, retransmit, out-of-order) over the tunnel |
| `poc/remote_xpc.py` | RSD: minimal HTTP/2 + Apple XPC objects, returns the service-port map |
| `poc/device_services.py` | length-prefixed plists, RSDCheckin, AFC upload, house_arrest, `installation_proxy` |
| `poc/mdns.py` | Bonjour register/browse; DNS-SD on a-Shell, raw mDNS on Linux |
| `poc/pair_install.py` | the CLI orchestration (pair → UDID → tunnel → install → pairing file) |

No pip process, no engine download, no native wheel, no GPL runtime. `install.sh` only fetches files
and then runs `pair --check`.

**Important protocol fact:** the RPPairing tunnel is **TLS 1.2 PSK**, not TLS 1.3. The iOS-negotiated
suites are CBC-SHA (`0x00AF`/`0x008C`), exactly what MIT `idevice` implements and what the Linux
interop test proves against OpenSSL.

## What to run now

1. `python3 poc/bonjour_check.py` — **already run (2026-11-15):** every type returns `NoAuth`, bind
   5353 fails and multicast send has no route. Raw mDNS is not available; see option D below.
2. The self-update command is `sh bin/update` (now also `sh bin/barisign update`); it must print a
   moving `files ....` indicator, then `files ok`, `check ok`, `ready`. There is no separate
   `engine` step: the check already imports the pure engine.
3. `sh bin/barisign pair --check` — must import the engine.
4. Pairing cannot work from a-Shell until an advertising host exists. The options are below.

## Options after the -65555 blocker (need a user decision)

- **A. Pairing host with the right `Info.plist` on the signer.** A small native helper (or a fork of
  SideInstaller/a-Shell) advertises `_remotepairing-pairable-host._tcp` and runs the Pair-Setup
  responder; BariSign keeps signing and the pure tunnel/install. This is the reliable path. It adds
  one **signer-side** app, not a target-side app. Bootstrap of the helper still needs a developer
  source (SideStore/AltStore/PC once).
- **B. Use SideInstaller (or SideStore/AltStore) on the signer for pairing only**, then feed the
  resulting `PairingFile_RemoteRP.plist` to BariSign. The target installs nothing from BariSign; the
  third-party app is on the signer. This violates the current "no third-party app" decision but is
  the shortest path.
- **C. One-time computer.** Pair the target with a Mac/Xcode Device Hub, copy the Mac's remote
  pairing record to `state/PairingFile_RemoteRP.plist`, then `sh bin/barisign pair --udid UDID`
  installs from a-Shell. No third-party app; a computer is needed once.
- **D. Raw mDNS fallback — RULED OUT (device, 2026-11-15).** `pair --raw-mdns` fails with
  `raw mDNS: multicast send failed: [Errno 65] No route to host`. iOS requires the multicast
  entitlement to send multicast; a-Shell does not have it (same class of blocker as the missing
  `NSBonjourServices` entry). No code running inside a-Shell can advertise the pairing host.
- **E. Host-initiated pairing (signer dials the target) — RULED OUT for iOS 27.** SideInstaller
  proved on devices (issues #52, two networks): iOS 27 lockdownd resets Wi-Fi pairing TCP
  immediately, no Trust prompt; "the way iOS 27 pairs over a network is the device-initiated one".
  pymobiledevice3's own manual-pairing command targets Apple TV/visionOS only
  ("Standard iOS devices usually do not need this"). A fresh iPhone listens on nothing until it
  sees a pairable host in Settings — so there is nothing to dial. Our `pairing.py` responder is
  the right side of the protocol; it is the advertisement that cannot run in a-Shell.
- **E. Fork a-Shell** with the `NSBonjourServices` entry and distribute it. Developer-only, not an
  end-user path.

### Importing a pairing file (supports C and B)

`sh bin/barisign pair --import FILE --host <target-ip>` now imports a pairing record produced by a
host that can advertise (Mac/Xcode, AltServer/AltStore, SideInstaller, …). It normalizes
`host_identifier`/`host_alt_irk`, accepts a 32- or 64-byte Ed25519 private key, writes the
`state/PairingFile_RemoteRP.plist` / `ALTPairingFile.*` copies, and can go straight to the tunnel.
`--host` defaults the port to **49152** (the device's RPPairing service); override with `--port`.
The target's LAN IP is in **Settings → Wi-Fi → IP Address**. No mDNS is needed on the signer.

## Acceptance gates

1. `sh bin/update` clean; files/engine synced; no repeated curl/git; no pip.
2. `pair --check` imports on a-Shell with cryptography 3.4.8, no qh3/sslpsk/native wheel.
3. **Blocked:** pairing from Settings cannot be advertised by a-Shell (`-65555`). Needs option A–D.
4. **Conditional:** with a pairing record from elsewhere, `pair` installs over Wi-Fi with the pure
   engine; target trusts the developer and the app opens.
5. Signing/portal/UDID page/self-update still work.

## Where it can still fail (device-only unknowns)

- **Bonjour browse/registration in a-Shell.** Registration is the existing DNS-SD shim; browsing was
  added with `DNSServiceBrowse`/`DNSServiceResolve`. If the target's `_remotepairing._tcp` is not
  found, the tool reports it after three 4-second attempts. Debug path: pass `--host <target-ip>
  --port <port>`; the port can be read from a Mac's `dns-sd -B _remotepairing._tcp` or from the
  target's Paired Macs screen by a second session.
- **Pairing host visibility.** If BariSign does not appear in Paired Macs: allow **Local Network**
  in a-Shell, same Wi-Fi, and confirm the signer's mDNS registration did not fail.
- **Pair-verify after pairing.** The target recognizes the host by `identifier`; if the record is
  stale, `pair --repair` generates a new host identity so the target offers a fresh pairing prompt.
  The same applies if `state/PairingFile_RemoteRP.plist` is deleted while `state/pairing_host.plist`
  is kept: the target will not prompt again for the same identity, so use `--repair`.
- **Only a link-local IPv6 address is advertised.** `--host <routable-ip> --port <port>` bypasses
  Bonjour; the port is the `_remotepairing` SRV port. Home Wi-Fi normally advertises IPv4.
- **Tunnel/TCP details.** The TCP client was proven against the Linux kernel (1 MiB echo, two
  connections, 300 KiB AFC upload through RSD); the device's window/ACK behaviour may still differ.
  The log shows which stage failed.
- **installation_proxy options.** It sends `PackageType: "Developer"`; if iOS 27 rejects it, the
  response text is printed verbatim.
- **Pairing file path.** Written after install via house_arrest; if the app is not installed yet or
  the bundle id is unknown, the step is skipped and the copies in `state/` remain for manual import.

## Linux tests (all should pass here)

```
python3 tests/test_protocol.py        # XPC, AFC, RSD, mDNS, OPACK, SRP, SipHash vectors
python3 tests/test_tls_psk.py         # TLS 1.2 PSK interop with OpenSSL, both suites
python3 tests/test_pairing_host.py    # full Pair-Setup round-trip (mock target)
python3 tests/test_pair_tunnel.py     # pair-verify + TLS-PSK + CDTunnel (mock device)
python3 tests/test_tcp6.py            # TCP stack against the Linux kernel through TUN
python3 tests/test_rsd_over_tcp.py    # RSD + AFC 300 KiB + installation_proxy over that stack
```

The TUN tests use `sudo` to create a point-to-point IPv6 interface (`baritun`); they are Linux-only.

## Constraints that still apply

- Everything on the signer is pure Python + the shipped `cryptography`; never add a native wheel.
- Keep `sh bin/update` self-updating: `install.sh` must remain the single file it applies.
- Do not name or describe the user's test hardware; use signer/target roles.
- Do not claim device success without the user's confirmation. Mark untested code **untested**.
- `third_party/sideinstaller/` stays isolated (non-commercial); never copy it into `poc/`.
- Prefer the MIT `jkcoxson/idevice` sources for protocol changes; `pymobiledevice3` is GPL reference
  only and is no longer installed.
