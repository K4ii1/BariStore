# AGENTS.md — BariStore

Project goal: **BariStore** — a 100% MIT, on-device iOS/iPadOS App Store, IPA signer, and StikDebug-style JIT Enabler running inside **a-Shell** over **LocalDevVPN** (`10.7.0.1`), with no computer and no second device.

## Architecture & Rules

- **Single Command Entry Point:** `baristore` opens the Web UI in a-Shell's internal browser (`baristore update` self-updates in place).
- **100% Clean-Room MIT Stack (`baristore/`):**
  - `baristore/cli.py` — CLI launcher (`baristore`, `baristore update`).
  - `baristore/webui.py` & `baristore/ui_page.py` — Loopback HTTP server (`127.0.0.1` + 128-bit random token) and Single-Page App Store UI.
  - `baristore/apple.py` — Clean-room MIT Apple ID authentication (Anisette v1/v3, GrandSlam SRP-6a, 2FA, `AESGCM`) and Developer Portal client (`developerservices2.apple.com`).
  - `baristore/signer.py` — Pure-Python Mach-O 64-bit / Fat binary code signer, CMS builder, entitlement encoder, extension inspector/stripper, and bundle ID rewriter.
  - `baristore/pairing.py` & `baristore/mdns.py` — Device-initiated RPPairing host with pre-computed 3072-bit SRP-6a + 6-digit PIN, resilient multi-connection listener, and 250ms mDNS broadcast/unicast announcer.
  - `baristore/tunnel.py`, `baristore/tls_psk.py`, `baristore/tcp6.py`, `baristore/remote_xpc.py` — Pair-verify, TLS 1.2 PSK (`0x00AF`/`0x008C`), userspace IPv6/TCP stack, and HTTP/2 + XPC RSD client.
  - `baristore/device.py` — `lockdownd` + `amfi` (Developer Mode check/show/enable), `afc`, `house_arrest` (automatic pairing-file injection), `installation_proxy` (Install, Uninstall, Lookup), and `debug_proxy` (StikDebug-style JIT Enabler).
  - `baristore/sources.py` & `sources.json` — AltSource manager, multi-source app deduplicator, and runtime GitHub release resolver for SideStore, LiveContainer+SideStore, LiveContainer, and AltStore Classic.
  - `baristore/storage.py` — Persistent state in `state/` with automatic migration from legacy installs.
- **Bump `VERSION` in `baristore/__init__.py` on every functional commit.**
