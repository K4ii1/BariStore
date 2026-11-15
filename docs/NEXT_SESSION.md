# Next session — handoff (2026-11-15)

State: version **0.9.0**, pure on-device pairing/tunnel/install engine, working tree clean after
commit. Signing, the developer portal, the UDID fallback page and the self-updater are unchanged and
still work. The **new engine is Linux-tested but not device-tested** — the device run below is the
only remaining gate.

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

## What the user should run (in order)

1. `sh bin/update` — must print `files ok`, `check ok`, `engine ok`, `ready`. No pip, no repeated curl.
2. `sh bin/barisign pair --check` — must import the engine and report
   `pure Python, no qh3/sslpsk/native wheel`.
3. `sh bin/barisign udid --pair` (or `sh bin/barisign pair --pair-only --timeout 180`):
   the signer prints `advertising as BariSign` and a 6-digit code; on the target open
   **Settings → Privacy & Security → Developer Mode → Paired Macs**, pick **BariSign**, enter the
   code. The signer must save the UDID and write
   `state/PairingFile_RemoteRP.plist` + `state/ALTPairingFile.*`.
4. `sh bin/barisign pair` — the signer installs the newest `*-signed.ipa` over Wi-Fi. On the target,
   trust the developer and open the app.

Run any failing step with `sh bin/barisign pair --debug` and send the full output. Do not retry the
same failing step more than twice; the next session needs the error text.

## Acceptance gates

1. `sh bin/update` clean; files/engine synced; no repeated curl/git; no pip.
2. `pair --check` imports on a-Shell with cryptography 3.4.8, no qh3/sslpsk/native wheel.
3. `pair --pair-only` pairs from Settings, saves the UDID and the normalized pairing file.
4. `pair` installs over Wi-Fi; the target trusts the developer and the app opens.
5. Signing/portal/UDID page/self-update still work; no PC, no AirDrop/OTA, no third-party app.

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
