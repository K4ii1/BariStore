# Next session — handoff (2026-11-17)

State: version **0.9.20**. `bin/` is retired: entry points are `sh barisign`, `sh update`, `sh barisignone` (one-device loopback experiment, defaults to safe `--pair-only --keep-awake` test). Experimental same-device path: `sh barisign pair --loopback --pair-only --keep-awake` (LocalDevVPN loopback + speech keep-alive; UNVERIFIED, see `docs/SINGLE_DEVICE.md` §5). `sh barisign` is the short form of `sh barisign` (same program; updates stay `sh update` + `sh install.sh`). The signer-hosted UDID page is **removed**: no HTTP server, no median link, no `--manual`/`--page` — pairing is the only UDID source (`sh barisign udid` pairs, or takes a pasted UDID). If Developer Mode cannot be opened with a plain unsigned IPA, the page comes back. Guided order is unchanged otherwise, guided flow reordered (Apple ID → devmode check → pairing/UDID →
variant → download → portal → sign → install). Signing, the developer portal, the UDID fallback
page and the self-updater are unchanged and still work. The download step now prints the
resolved version before fetching (`SideStore 0.6.0 (24.1 MB)`, nightly by asset date) and
`(cached, still current)` only when size + GitHub SHA-256 match — a stale cache can never
pass as current; offline it says `(no GitHub; using the saved file)`. Details:
`docs/SINGLE_DEVICE.md` §4.

**Pairing works from a-Shell (device-verified 2026-11-15/16).** DNS-SD itself is still blocked
(`-65555`: a-Shell's signed `Info.plist` has no `NSBonjourServices` entry), but raw broadcast
advertising works: the target lists BariSign, M1–M6 completes, the signer prints the PIN and
saves the UDID plus `state/PairingFile_*.plist`. `--repair` forces a fresh host identity when
the target stops offering a prompt.

`sh barisign udid` pairs and saves the UDID (or takes a pasted one), and `sh barisign pair` pairs by itself when no record exists. No page fallback.

## What changed

The `qh3`/`sslpsk`/`pymobiledevice3` route is gone. `sh barisign pair` now runs a self-contained
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

1. `sh update` — clean screen, `installing BariSign <version>`, `(1/2) files` cycling,
   clean screen, `(2/2) check`, clean screen, `BariSign <version> installed` + next step.
2. `sh barisign pair --check` — must import the engine.
3. `sh barisign pair` — pairs (raw broadcast is automatic on a-Shell) or reuses the
   record, finds the target by port scan + subnet sweep, then tunnels and installs with
   `installation_proxy`. Target: trust the developer, open the app.
4. If a step fails, rerun with `--debug` and send the output plus `state/pair_debug.log`.

## Discovery, as it stands (device-proven 2026-11-15)

- Pairing advertisement works via raw broadcast; the target lists BariSign, M1-M6 completes.
- Bonjour browse is dead on a-Shell (-65555), so discovery is: paired address -> port scan
  (49152 first) -> subnet sweep matching the pairing record. No address lookup needed.
- Remaining untested on a device: tunnel + RSD + AFC + `installation_proxy` install, and the
  pairing-file write into the app.

## Background options (only if the current path stalls)

Single-device/background was investigated against the a-Shell sources on
2026-11-17 and is **settled, not a fallback**: one device cannot pair with or
install on itself (Paired Macs lists remote hosts; loopback/LocalDevVPN does
not create a pairing record), a-Shell has no ActivityKit/notification API for
Python, and its three Shortcuts intents force the app open and are
time-boxed. Keep a-Shell foreground (iPad Split View/Stage Manager only keeps
it visible). Full analysis: `docs/SINGLE_DEVICE.md`. What works with one
device: `pair --check`, `login`, `portal` (saved UDID), `sign`, `status`.

- **A. Pairing host with the right `Info.plist`.** Reliable but needs a developer source once.
- **B. SideInstaller on the signer for pairing only**, then `--import` the record. Works but
  violates the no-third-party goal.
- **C. One-time computer** for the pairing record, then `--udid` installs from a-Shell.
- **E. Host-initiated pairing — RULED OUT for iOS 27** (SideInstaller #52: lockdownd resets
  Wi-Fi pairing TCP; only device-initiated works).

## Acceptance gates

1. `sh update` clean; files/engine synced; no repeated curl/git; no pip.
2. `pair --check` imports on a-Shell with cryptography 3.4.8, no qh3/sslpsk/native wheel.
3. `pair --pair-only` pairs from Settings over raw broadcast, saves the UDID and the pairing file.
4. `pair` finds the target (paired address → port scan → subnet sweep), installs over Wi-Fi;
   target trusts the developer and the app opens.
5. Signing/portal/self-update still work; no PC, no AirDrop/OTA, no third-party app.

## Where it stands (device, 2026-11-15 evening)

**Pairing works.** Broadcast discovery shows BariSign on the target; the full M1–M6 runs, the
signer prints the PIN and saves the UDID (`00008110-…` ECID form) plus `state/PairingFile_*.plist`.
Frame log: `state/pair_debug.log` (every RX/TX frame; send it back after any pairing run).

**Discovery without Bonjour:** browse is skipped on a-Shell and any -65555 is remembered in
state so later runs never try. Fallback chain: paired address → port scan (49152 first) →
subnet sweep matching the handshake identifier against the pairing record. When the sweep finds
open ports but nothing matching, plain `pair` pairs fresh automatically (new identity → prompt
on the target) instead of dying on the stale address. Errors are one plain line
(awake/unlocked/same-Wi-Fi); `--debug` and `state/pair_debug.log` only on failure.
`--host <ip>` skips all of this.

**Install path (device):** the tunnel reaches AFC upload; `FILE_OPEN` answers with opcode `0x0E`
(`FILE_OPEN_RES`), which the client now accepts. Before uploading, `install` runs a preflight on
the signed IPA's embedded profile (expiry, target UDID, certificate dates) and refuses with a
portal+sign pointer instead of failing at 40% with a bare ApplicationVerificationFailed — this
covers the stale-asset case (e.g. installed days after signing, past the 7-day free profile).
Still untested end to end on a device, as is the pairing-file write into the app. Pair UI is staged
(Pair → Tunnel → Install → Done) with screen clears like the guided flow; a duplicate second
connection is refused while one pair-setup runs. Run `sh barisign pair` (plain; raw advertisement is now
automatic on a-Shell, `--raw-mdns` only forces it elsewhere).

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

Portal now also registers an App Group (`group.<bundle>.<team>`, LiveContainer special-cased
to `group.com.SideStore.SideStore.<team>`), enables APG3427HIY on the App ID and assigns the
group — protocol shape from MIT isideload. Without it the installed SideStore/LiveContainer
cannot open its app-group container. The signer stamps the granted group into ALTAppGroups
(isideload behavior); unknown/custom apps keep the old strip-ungranted rule. If Apple refuses
groups for the team, portal warns and continues without them.

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
- Keep `sh update` self-updating: `install.sh` must remain the single file it applies.
- Do not name or describe the user's test hardware; use signer/target roles.
- Do not claim device success without the user's confirmation. Mark untested code **untested**.
- `third_party/sideinstaller/` stays isolated (non-commercial); never copy it into `poc/`.
- Prefer the MIT `jkcoxson/idevice` sources for protocol changes; `pymobiledevice3` is GPL reference
  only and is no longer installed.
