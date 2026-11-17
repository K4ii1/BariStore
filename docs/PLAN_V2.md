# BariSign — plan v3 (one iPhone, no computer, web UI)

Written 2026-10-29 as two roles, rewritten 2026-10-31 after AirDrop was refused, rewritten
again 2026-11-17: **siboot proved the missing pieces** (MIT, FrizzleM) — Developer Mode over
the tunnel and a loopback page UI — so the second device is gone. The current shape is **one
iPhone that signs for itself**:

```
THIS IPHONE (a-Shell + BariSign + LocalDevVPN)
  0. requirements  LocalDevVPN answers on 10.7.0.1 (wait loop)
  1. Apple ID      anisette + SRP-6a + 2FA (saved session reused while Apple accepts it)
  2. portal        pick the developer team (saved next time, no question)
  3. pair          RPPairing host over broadcast; Settings > Developer > Paired Macs
                   on the SAME iPhone; UDID from M5; pairing file saved.
                   Skipped when this run just paired (one PIN per run);
                   retry loop with a live timer if the target never shows.
  4. variant       SideStore / LC+SideStore / AltStore / custom IPA (tap to choose)
  5. download      live-resolved IPA, size + SHA-256
  6. devmode       lockdownd GetValue; show switch (action 0) or turn on (action 1).
                   Turning it on restarts the iPhone: the run ends with a restart
                   card and the rerun jumps straight back here to verify.
  7. sign & install  register device, App ID (+ App Group), certificate, profile;
                     sign + verify; installation_proxy over the loopback tunnel
                     (Trust Developer, open the app)
```

`barisign` runs it as a web page (a-Shell internal browser sheet over the terminal);
`barisign shell` runs the same pipeline in the terminal. Backend and page talk JSON over
127.0.0.1 with a per-run token (siboot's page security model).

## Why not AirDrop or OTA

iOS 27 refuses a **free provisioning profile** from the AirDrop/MobileInstallation source
(`MIInstallerErrorDomain` 111). The same IPA installs through a developer
`installation_proxy` source, which is what the loopback tunnel is. OTA is enterprise/ad-hoc
territory and is not available with a free certificate. Both are out.

## Why the UDID comes from pairing

The UDID is needed for the profile, and pairing reports it (M5). No page, no profile-service
round-trip: removed in 0.9.18.

## Developer Mode without a second device or a trigger install

Over the open tunnel, lockdownd answers `GetValue` for `DeveloperModeStatus` in domain
`com.apple.security.mac.amfi` (as pymobiledevice3 reads it), and AMFI's RSD shim
(`com.apple.amfi.lockdown.shim.remote`) takes `{"action": 0}` to reveal the switch and
`{"action": 1}` to turn it on (as MIT idevice implements it; siboot documents the flow).
Show needs no restart; turn-on restarts (refused with a passcode set — then show + manual
flip). iOS closes AMFI after one request, so each action gets a fresh connection.
`poc/devmode.py` is clean-room code from those MIT sources; `pair --devmode status|show|on`
runs each step alone.

## The page instead of the terminal

a-Shell's `openurl` with `BROWSER=internalbrowser` shows a WKWebView sheet over the terminal:
the app stays foreground, so iOS never pauses the run. The page is served from this iPhone's
loopback only, every path starts with 128 random bits that die with the run, and the Host
header must name the loopback. Pairing still hops to Settings for the PIN; the page plays
silence through WebAudio meanwhile (a-Shell has background audio). There is intentionally
no speech fallback in the web flow: the terminal `shell` fallback keeps its own
`--keep-awake` speech loop, the page stays silent. A Wake Lock request keeps the
screen awake during pairing/install. Terminal line-strain is gone by construction:
the flow's stdout goes to the page log, questions arrive as form fields and buttons,
a revision counter re-renders the main card only when the question changes, and a
collapsible log never reloads under typing hands. Update and export buttons live in
the Settings card (`/api/update` runs `barisign update` in a thread and reports back;
`/api/export` copies the pairing file to `~/Documents/BariSign-Pairing.plist`).

## Pairing file

Still written after install via house_arrest so the installed app can refresh itself:
AltStore `Documents/ALTPairingFile.plist`; SideStore `Documents/ALTPairingFile.mobiledevicepairing`
plus `PairingFile_RemoteRP.plist` (newer nightlies read the per-protocol file);
LiveContainer's built-in SideStore the same two names under `SideStore/Documents/`.
The fork plan (`docs/FORK_PLAN.md`) — a pairing step inside our own app builds — stays future
work; the web UI + devmode toggle reduced its urgency, but refresh UX still wants it.
