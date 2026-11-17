# BariSign — plan v2 (two roles, no computer, no Shortcuts)

Written 2026-10-29, rewritten 2026-10-31 after the AirDrop install was refused by iOS 27,
updated 2026-11-17 (0.9.17: broadcast pairing verified, App Groups registered, version shown
at every download). The current
shape is **two roles**, not two specific devices:

- **Signer** — runs a-Shell + BariSign: UDID page, Apple ID, portal, signing, install.
- **Target** — the device that gets the app: Safari and Settings only.
- Either role may be an **iPhone or an iPad** (iOS/iPadOS 27+); they must share the same Wi-Fi.

## The shape of it

```
SIGNER (a-Shell)                              TARGET (Safari / Settings)
  0. Apple ID anisette + SRP-6a + 2FA          (verified)
  1. Developer Mode present? else trigger      (verified path)
  2. pair     broadcast as BariSign + code -->  Settings -> Developer -> Paired Macs -> BariSign
              read the UDID from the pairing/tunnel (device-verified M1–M6)
  3. variant, then download: resolve live, show version, size + SHA-256 (0.9.17)
  4. portal   UDID -> App ID -> App Group + cert -> profile (verified, incl. APG3427HIY)
  5. sign the chosen IPA (verified) + preflight before upload
  6. install over the same pairing             installation_proxy over Wi-Fi
                                              (target Trust Developer, opens the app;
                                               on-device install is the remaining gate)
  fallback: signer serves http://<signer-ip>:<port>/; target installs median.co/udid,
            copies the UDID and submits it (only if pairing cannot provide one)
```

Single device cannot cover steps 2+6 on itself, and there is no background
keep-alive (no ActivityKit/notifications/Shortcuts path) — `docs/SINGLE_DEVICE.md`.
Keep a-Shell foreground for `pair` (iPad Split View is fine).

a-Shell is installed **only on the signer**. The target installs nothing from BariSign. The program stays
one integrated flow on the signer.

## Why not AirDrop or OTA

iOS 27 refuses a **free provisioning profile** from the AirDrop/MobileInstallation source:

```
MIInstallerErrorDomain 111
"authorized by a free provisioning profile, but apps validated by those are not allowed
to be installed from this source."
```

The same IPA installs through a developer `installation_proxy` source, which is what the signer→target
pairing tunnel does over Wi-Fi. OTA is enterprise/ad-hoc territory and is not available with a free
certificate. Both are out.

## Why the UDID is a page, not a paste into a-Shell

The target is the device that needs the UDID, and it does not run a-Shell. The normal route is the pairing: the signer pairs the target, reads the target's UDID from the
pairing/tunnel, and uses it for the profile. If that is unavailable, the signer starts a short-lived
HTTP server on its Wi-Fi address; the target opens it in Safari, installs the `median.co/udid` profile,
copies the value and submits it. `sh bin/barisign udid --manual` keeps a paste-on-the-signer fallback
for development.

## Pairing file — decided: fork the three apps

**Decision (2026-10-29): fork.** The pairing module goes into the start screen of SideStore, of the
SideStore inside LiveContainer+SideStore, and of AltStore Classic. `docs/FORK_PLAN.md` holds the design,
the licence rules (clean-room reimplementation — the non-commercial SideInstaller code may not be mixed
into AGPL forks) and the risks.

Facts that make it possible, checked 2026-10-29/31:

- iOS **27** added **Settings → Privacy & Security → Developer Mode → "Paired Macs"** with a six-digit
  code. SideInstaller uses this to pair with no computer.
- SideStore, AltStore and LiveContainer also accept an **imported** pairing file, which is how the module's
  output gets consumed.
- The pure engine implements the device-initiated pairing host, pair-verify, the TLS 1.2 PSK tunnel,
  a userspace TCP stack, RSD and `installation_proxy`; `bin/barisign pair` is the first implementation
  of that route, written from the MIT `idevice` protocol sources.
- Licences: SideStore **AGPL-3.0**, AltStore **AGPL-3.0**, LiveContainer **AGPL-3.0**; SideInstaller is
  "Other"/non-commercial and stays isolated in `third_party/sideinstaller/`. The engine is MIT and
  uses no GPL runtime; `pymobiledevice3` is a protocol reference only.

Cost accepted with the decision: our patch to three AGPL projects, rebuilt on every upstream release, plus
the `bin/barisign pair` engine on the signer.

## Status

- Verified on the signer (iOS 27): Apple sign-in, portal, signing, app launch.
- The tunnel/install engine is now pure Python (`poc/tls_psk.py`, `tcp6.py`, `remote_xpc.py`,
  `device_services.py`, `pairing.py`, `rpp_tunnel.py`, `mdns.py`); no pip, no qh3, no native wheel.
  All layers pass their Linux tests.
- **Device blocker:** a-Shell cannot advertise `_remotepairing-pairable-host._tcp`
  (`DNSServiceRegister -65555`, NoAuth; its signed Info.plist lacks `NSBonjourServices`). The target
  cannot discover BariSign from a-Shell. The install engine is ready once a pairing record exists.
  Options: `docs/NEXT_SESSION.md`.
