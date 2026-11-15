# Next session — handoff (2026-11-15)

State: version **0.8.8**, HEAD **33c228f**, working tree clean, self-updater in place.
This file is the handoff for the one remaining engineering problem: a **pure a-Shell** RPPairing
tunnel that installs the signed IPA on the target without a PC, without a native wheel and without
a third-party app.

## What works now

- `sh bin/barisign` — guided signer flow: variant, UDID, Apple sign-in, portal, signing.
- `sh bin/update` — self-updating bootstrapper: reads the newest `install.sh` (pinned to the newest
  commit) and applies every file, including itself. No manual curl/git.
- Signing/portal/UDID page; signed IPA is valid.
- `sh bin/barisign pair` exists but is blocked on a-Shell (see below).
- Two roles: **signer** (a-Shell + BariSign) and **target** (Safari + Settings only); either may be
  an iPhone or iPad, both iOS/iPadOS 27+, same Wi-Fi. No PC, no AirDrop, no OTA, no SideInstaller,
  no enterprise certificate.

## The blocker

`pymobiledevice3` 11.49.0's RPPairing tunnel imports **qh3**, a compiled QUIC library. PyPI has no
iOS wheel for any qh3 release (0.15–2.1 checked); a-Shell cannot build native extensions. pip falls
back to the sdist and dies preparing qh3 metadata. The **TCP** tunnel path needs **sslpsk**, also
native. `aioquic` is pure Python but needs native `pylsqpack` and `cryptography>=43`; not usable with
a-Shell's shipped `cryptography` 3.4.8.

`pair_install.py` currently detects a-Shell/iOS and exits with code 2, explaining this. `install.sh`
and `bin/update` treat that as "engine unavailable, signing still works".

## The one component to build

A **pure-Python TLS-PSK tunnel** that replaces `sslpsk` (and avoids qh3), or an equivalent pure
QUIC. The more tractable route:

1. **Keep** pymobiledevice3's pure-Python `userspace_tunnel`/`pmd-pytcp` TCP stack and
   `installation_proxy`/RSD code.
2. **Replace** `sslpsk` with a pure-Python **TLS 1.3 PSK** client (HKDF key schedule, transcript,
   AEAD with cryptography 3.4.8: AES-GCM/ChaCha20-Poly1305, SHA-256).
3. Open the RPPairing tunnel over TCP, let `pmd-pytcp` carry RSD/RemoteXPC, then run
   `installation_proxy`.
4. Remove the qh3 dependency from imports (a stub for the QUIC classes is enough for the
   pairing-only path; the install path must not touch qh3).

References (read, do not blindly copy):

- `jkcoxson/idevice` — **MIT** — `remote_pairing`, `tunnel_tcp_stack`, RPPairing host, TLS-PSK
  tunnel, AFC/house_arrest, `installation_proxy`. The preferred clean-room source.
- `pymobiledevice3` — **GPL-3.0** — `remote/tunnel_service.py`, `remote/userspace_tunnel.py`,
  `services/installation_proxy.py`, `services/house_arrest.py`. Protocol reference; do not copy GPL
  code into MIT files; keep any GPL-derived file isolated and documented.
- `FrizzleM/SideInstaller` — non-commercial, isolated in `third_party/sideinstaller/`; architecture
  reference only. Never mix it into AGPL forks or MIT files.
- `sslpsk`/OpenSSL TLS-PSK semantics; `idevice`'s tunnel implementation is the known-good behaviour.

## Useful facts already verified

- The RPPairing host itself (SRP-6a, Ed25519, pairing record) is pure Python and does not use qh3 at
  runtime; the qh3 import is only at module top. A qh3 **import stub** can let
  `serve_pairable_host` run and produce the pairing record/UDID. The **install tunnel** is the part
  that must be pure.
- `pmd-pytcp` (pure asyncio TCP stack) and `pymobiledevice3`'s `userspace_tunnel` are pure Python.
- Pairing record keys expected by AltStore/SideStore: AltStore `Documents/ALTPairingFile.plist`;
  SideStore `Documents/ALTPairingFile.mobiledevicepairing`; RPPairing keys `public_key`,
  `private_key`, `identifier`, `alt_irk`. `pair_install.py` already normalizes
  (`host_identifier`→`identifier`, `host_alt_irk`→`alt_irk`) and writes via house_arrest/AFC.
- `pymobiledevice3` is pinned to **11.49.0**; `install.sh`/`bin/update` use one pip process with
  `--only-binary=:all:` and a clean `state/pymd3`. Do not reintroduce qh3/sslpsk/cryptography
  upgrades.
- a-Shell ships `cryptography` 3.4.8; it has RSA, Ed25519, X25519, ChaCha20-Poly1305, HKDF, SHA-256,
  AES-GCM and `_serialization`. Do not vendor/replace cryptography (native extension).

## Files

- `poc/barisign.py` — CLI, guided flow, UDID HTTP page, `pair` command.
- `poc/pair_install.py` — engine install, pairing host, tunnel, install, pairing-file writer.
- `poc/ashell_bonjour.py` — DNSServiceRegister shim for pymobiledevice3's mDNS on a-Shell.
- `install.sh` — one instruction file: fetch all files pinned to a commit, install engine once.
- `bin/update` — self-updating bootstrapper (fetch newest install.sh and run it).
- `docs/PAIRING_INSTALL.md`, `docs/RESULTS.md`, `AGENTS.md` — constraints and verified facts.

## Acceptance gates

1. `sh bin/update` clean; no repeated curl; files/engine synced.
2. `sh bin/barisign pair --check` imports the engine on a-Shell **without qh3/sslpsk/native wheels**
   and with `cryptography` 3.4.8.
3. `sh bin/barisign pair --pair-only` pairs the target from Settings, saves the UDID and writes the
   normalized pairing file, with **no** qh3/sslpsk.
4. `sh bin/barisign pair` installs the signed IPA over Wi-Fi with `installation_proxy`; target
   trusts the developer and the app opens.
5. Signing/portal/`sh bin/update` still work; no PC, no AirDrop/OTA, no third-party app/cert.
6. Label anything not device-tested **untested**; never claim success without the user's device run.

## Process

- Linux unit tests for the TLS-PSK state machine (RFC 8448 vectors where possible), packet framing,
  HKDF/transcript, and the userspace TCP path. No device access here.
- Keep the self-updater and signing path untouched; add the pure tunnel behind the existing
  `pair_install` interface.
- If the same failure happens twice, stop and report instead of guessing.
- Do not name test hardware; use signer/target roles.
