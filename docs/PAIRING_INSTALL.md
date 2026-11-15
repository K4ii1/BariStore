# Pairing + `installation_proxy` on iOS 27 — what is possible

Status (2026-11-15): **the pure route is implemented.** `sh bin/barisign pair` now pairs the target
from Settings, opens the RPPairing tunnel and installs the signed IPA with `installation_proxy`,
entirely in a-Shell with no pip, no native wheel and no second app. The engine is Linux-tested; the
**on-device run is the remaining gate** (`docs/NEXT_SESSION.md`).

The question was: can BariSign install its signed IPA on the **target** with **no computer**, using
pairing plus `installation_proxy`, and generate pairing files that AltStore and SideStore can use?

Short answer: **yes, with a self-contained pure-Python protocol stack.** `pymobiledevice3` itself is
not usable here (it imports `qh3`, and its recent releases use `cryptography` APIs newer than
a-Shell's 3.4.8), so BariSign implements the needed subset from the MIT `jkcoxson/idevice` sources and
Apple's public formats.

## 0. The pure route, as built

1. **Pairing host.** `poc/pairing.py` advertises
   `_remotepairing-pairable-host._tcp` through the system DNS-SD API. The target pairs from
   **Settings → Privacy & Security → Developer Mode → Paired Macs**; the signer prints the PIN. The
   exchange is Apple Pair-Setup M1–M6: SRP-6a (3072-bit group, SHA-512), TLV8, ChaCha20-Poly1305 and
   an OPACK identity blob. The signer saves its Ed25519 identity and the normalized record in
   `state/` (`PairingFile_RemoteRP.plist`, `ALTPairingFile.plist`,
   `ALTPairingFile.mobiledevicepairing`).
2. **UDID.** The target's `remotepairing_udid` arrives in M5. If it is empty, the signer opens the
   tunnel once and reads `UniqueDeviceID` from the RSD handshake.
3. **Discovery.** `poc/mdns.py` browses `_remotepairing._tcp` (`DNSServiceBrowse`/`Resolve` on
   a-Shell, raw mDNS on Linux), preferring the target's source IP from the pairing connection and
   then the UDID from the TXT record. `--host/--port` bypasses discovery for debugging.
4. **Control channel.** `poc/rpp_tunnel.py` connects to the target's `_remotepairing` port, runs
   pair-verify (X25519 + Ed25519 + ChaCha20-Poly1305), and asks for a TCP listener.
5. **Tunnel.** It connects to that port and runs a **TLS 1.2 PSK** handshake (`0x00AF`
   `AES-256-CBC-SHA384` or `0x008C` `AES-128-CBC-SHA`) with the X25519 shared secret as the PSK, then
   the `CDTunnel` handshake. The result carries raw IPv6 packets. **TLS 1.3 is not what iOS uses
   here**; the TLS 1.2 PSK suites are the tested path.
6. **Userspace TCP.** `poc/tcp6.py` implements the small TCP client the tunnel needs (no TUN, no
   root): handshake, cumulative ACKs, MSS segmentation, retransmission, out-of-order receive.
7. **RSD.** `poc/remote_xpc.py` speaks the minimal HTTP/2 + XPC handshake Apple's RSD uses (empty
   HEADERS, no HPACK) and returns the service-port map.
8. **Services.** `poc/device_services.py` uses the classic length-prefixed plist framing for RSD
   check-in, AFC upload to `/PublicStaging`, `installation_proxy` with
   `PackageType: "Developer"`, and house_arrest to write the pairing file into the installed app.

Commands (all on the signer):

```sh
sh bin/barisign pair --check                 # imports the pure engine; no qh3/sslpsk/native wheel
sh bin/barisign udid --pair                  # pair, save the UDID and the pairing file
sh bin/barisign pair                         # pair (if needed) and install over Wi-Fi
sh bin/barisign pair --pair-only --timeout 180
sh bin/barisign pair --ipa FILE              # a specific signed IPA
sh bin/barisign pair --host IP --port PORT   # skip Bonjour (debugging)
sh bin/barisign pair --repair                # new host identity: the target offers a new prompt
sh bin/barisign pair --debug                 # traceback on failure
```

There is no engine install: `install.sh` only fetches the program files, and `pair --check` proves
the imports. The Linux tests for each layer are in `tests/` (TLS-PSK interop with OpenSSL, a full
Pair-Setup round-trip, pair-verify + tunnel against a mock device, the TCP stack against the Linux
kernel through TUN, and RSD + AFC + `installation_proxy` over that stack).

### Licensing

The engine is MIT. Protocol references: `jkcoxson/idevice` (MIT) and Apple's public pairing/XPC/AFC
formats; `pymobiledevice3` (GPL-3.0) is read as a reference only and is **not** installed or copied.
`third_party/sideinstaller/` remains isolated under its non-commercial licence and is never mixed
into `poc/`.

## 1. Why AirDrop and OTA are out

Device log from the target (iOS 27, AirDrop):

```
MIInstallerErrorDomain Code=111
"The bundle ... is authorized by a free provisioning profile, but apps validated by
those are not allowed to be installed from this source."
LegacyErrorString=ApplicationVerificationFailed
```

`MobileInstallation` sets `allowingFreeProfileValidation=false` for the AirDrop source. The
same IPA installs through a developer `installation_proxy` source, which
sets it true. OTA (`itms-services`) is enterprise/ad-hoc territory; a free profile is not
accepted from it either. So:

- AirDrop: **dead** for free-profile apps.
- OTA: **dead** without a paid/enterprise certificate.
- A developer-source `installation_proxy` install: **works** (used only to verify the signature; not part of BariSign).
- `installation_proxy` over a **pairing tunnel**: the only remaining no-computer route.

## 2. How the on-device route works

The pieces, in order:

1. **RPPairing host.** An app on one device advertises
   `_remotepairing-pairable-host._tcp` over Bonjour and runs the pairing responder. The other
   device (or the same device, via Settings) sees it under
   *Settings → Privacy & Security → Developer Mode → Pair with …*, pairs, and the host gets an
   **RPPairing record** (`public_key`, `private_key` 32-byte Ed25519, `identifier`, `alt_irk`).
   The host shows a **PIN**; the pairing client types it.
2. **LocalDevVPN.** On the device that will install to itself, the RPPairing service is
   reachable at the VPN peer address (default `10.7.0.1:49152`). LocalDevVPN (App Store) creates
   that local tunnel; SideStore's docs make it mandatory for install/refresh, and SideInstaller
   uses the same address.
3. **Tunnel + RSD.** The pairing record opens a `tunnel_create_rppairing` connection; inside it
   runs RemoteServiceDiscovery/RemoteXPC, and then `installation_proxy` (and
   `installcoordination_proxy` on newer iOS).
4. **AFC / house_arrest.** The same tunnel copies files into an app container, e.g. the signing
   IPA into `/PublicStaging`, or a pairing file into SideStore/AltStore's Documents.

The host must stay alive while the pairing client is in Settings. SideInstaller does this with a
Live Activity (the PIN in the Dynamic Island/Lock Screen) plus a keep-alive helper. A-Shell has
none of that: it is suspended when Settings comes to the front.

## 3. What is already proven

### SideInstaller (open source, non-commercial)

- README: *"Install SideStore and LiveContainer directly on your iPhone. No PC required."*
  iOS 27+ works on-device; iOS 26.4–26.x needs a remote pairing file made on a PC.
- Requires **LocalDevVPN** and Wi-Fi.
- The app runs the RPPairing host itself, pairs this iPhone through Settings, opens the tunnel,
  signs with the user's own Apple ID and installs.
- **Side by Side** installs SideInstaller onto *another* iPhone on the same Wi-Fi: the target
  pairs from its Settings, the host advertises the pairing service; no VPN needed for that
  direct Wi-Fi path. That is a no-PC bootstrap for the second device.
- Its Rust core uses `jkcoxson/idevice` with `remote_pairing`, `tunnel_tcp_stack`, `rsd`,
  `installation_proxy`, `installcoordination_proxy`, `afc`, `house_arrest`, `misagent`.
- License: custom **non-commercial, source-only**. It may not be mixed into the AGPL forks.

### AltStore Classic 2.3

Source-verified in `AltStore/Managing Apps/OnDeviceClient.swift`:

- The pairing file must contain an **RPPairing** record: `record["private_key"] != nil`.
  Lockdown-style records are rejected.
- It opens `tunnel_create_rppairing` at port **49152** with the default PIN `000000`.
- It installs through `/PublicStaging/<bundle>.ipa` and `installation_proxy`.
- The file lives at `Documents/ALTPairingFile.plist` on the device (AltServer normally embeds
  it during install).

So once AltStore has an RPPairing file, it can install/refresh by itself. The missing piece is
getting that file onto the device without a PC.

### SideStore

- `AppConstants.swift`: supported names include `ALTPairingFile.mobiledevicepairing`
  (legacy), `PairingFile_Lockdown.plist`, `PairingFile_RemoteRP.plist`.
- Issue #1698 and the docs: from **iOS 26.4** a lockdown-style pairing file is rejected through
  LocalDevVPN; a **remote (RPPairing)** file is required. The settings page can import one and
  set it as preferred.
- Docs: initial install still needs a computer (iloader); the on-device VPN is required for
  every install/update/refresh afterwards.

### Licensing of the building blocks

- `jkcoxson/idevice` — **MIT**. Includes the RPPairing host, `tunnel_tcp_stack`, RSD,
  `installation_proxy`, `installcoordination_proxy`, AFC/house_arrest, pairing-file helpers.
- `nab138/isideload` — MIT (auth, portal, signing).
- `pymobiledevice3` — GPL-3.0; useful as a protocol reference, but not a drop-in iOS tunnel.
- SideInstaller — non-commercial; **cannot** go into the AGPL forks. Its architecture is the
  reference, not the code.

## 4. The hard boundary

The pure-Python route may remove the need for a native helper; if it fails, the fallback is one. The
options, easiest first:

| Option | No PC? | Own Apple ID? | Work | Notes |
|---|---|---|---|---|
| **A. SideInstaller as bootstrap** | yes (app from its official page) | yes for installed apps; SideInstaller itself is a shared-cert build | none | Proven on iOS 27. LocalDevVPN. Then SideStore/AltStore run; SideInstaller can install a custom IPA. |
| **B. Fork SideInstaller into a BariSign installer** | yes, if distributed the same way | yes | medium | Non-commercial code, isolated from the AGPL forks. Bootstrap of the fork has the same problem as A. |
| **C. Clean native helper from MIT `idevice`/`isideload`** | yes, once installed | yes | large | AGPL-compatible. RPPairing host + tunnel + installation_proxy + AFC pairing-file writer. Still needs a bootstrap (PC once, or a shared-cert web install). |
| **D. a-Shell/Python on the signer, pure engine** | **yes (implemented)** | yes | done | `poc/` implements the subset itself: RPPairing host, TLS 1.2 PSK, userspace TCP, RSD, AFC, `installation_proxy`. No native app, no cert, no pip. Linux-tested; device run pending. |

There is **no** pure own-cert + no-PC + no-third-party-app path on iOS 27: a free-profile app
cannot be AirDropped or OTA-installed, and a free-signed helper can only be installed through a
developer source. A bootstrap app must therefore come from somewhere: an App Store app that can
do the native work (none today), a shared-cert build (SideInstaller), or a one-time PC install.

## 5. Pairing files BariSign would write

The host gets an RPPairing record. For compatibility:

| App | Path | Needs |
|---|---|---|
| AltStore Classic 2.3 | `Documents/ALTPairingFile.plist` | RPPairing (`private_key`), enough for `OnDeviceClient` |
| SideStore | `Documents/ALTPairingFile.mobiledevicepairing` | remote record on iOS 26.4+; lockdown half for older |
| LiveContainer + SideStore | `SideStore/Documents/ALTPairingFile.mobiledevicepairing` | same |
| Feather/StikDebug etc. | see SideInstaller's `PairingTargets` table | mixed |

A merged plist containing both the RPPairing keys and the lockdown keys is the safest for old and
new apps; AltStore ignores the lockdown half, SideStore uses the remote half on 26.4+. The file
is written over AFC/house_arrest, exactly as AltServer and SideInstaller do.

`bin/barisign pair` writes the record itself: `poc/pairing.py` stores our Ed25519 public/private
keys, `identifier` and `alt_irk` (plus `host_identifier`/`host_alt_irk` aliases for older consumers)
under `state/` as `PairingFile_RemoteRP.plist`, `ALTPairingFile.plist` and
`ALTPairingFile.mobiledevicepairing`. After a successful install it writes the appropriate file into
the installed app's container with `house_arrest`/AFC.

## 6. Recommended order

1. **Run the Linux tests** (they need no device): TLS-PSK interop, pairing host, pair-verify + tunnel,
   TCP, RSD + AFC + installation_proxy.
2. **Run the on-device gates** in `docs/NEXT_SESSION.md`: `pair --check`, `pair --pair-only`, `pair`.
   The signer stays in a-Shell; the target only uses Settings.
3. If a gate fails, report the exact output (use `--debug`). The next session fixes that layer; do
   not retry the same failing step twice.
4. **Do not** spend more time on AirDrop/OTA for free profiles.

## 7. Unverified / risks

- SideInstaller's iOS 27 no-PC claim is the author's and is consistent with the source, but this
  project has not independently run it on the target yet.
- The pure-Python tunnel has not run on a device yet. The risky details are the target's window/ACK
  behaviour under the userspace TCP stack, the DNS-SD browse on a-Shell, and whether iOS 27 accepts
  the exact `installation_proxy` options. Each failure has a precise message; see
  `docs/NEXT_SESSION.md`.
- AltStore 2.3's Remote AltServer is a separate feature; it is not the same as on-device
  RPPairing and still points at a server.
- Pairing-file compatibility across AltStore/SideStore versions changes quickly; test each
  release.
