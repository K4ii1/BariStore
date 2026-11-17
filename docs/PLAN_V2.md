# BariSign — plan v3 (one iPhone, no computer, web UI)

Written 2026-10-29 as two roles, rewritten 2026-10-31 after AirDrop was refused, rewritten
again 2026-11-17: **siboot proved the missing pieces** (MIT, FrizzleM) — Developer Mode over
the tunnel and a loopback page UI — so the second device is gone. The current shape is **one
iPhone that signs for itself**:

```
THIS IPHONE (a-Shell + BariSign + LocalDevVPN)
  0. requirements  LocalDevVPN answers on 10.7.0.1 (wait loop)
  1. Apple ID      anisette + SRP-6a + 2FA (saved session reused while Apple accepts it)
  2. variant       SideStore / LC+SideStore / AltStore / custom IPA
  3. download      live-resolved IPA, size + SHA-256
  4. pair          RPPairing host over broadcast; Settings > Developer > Paired Macs
                   on the SAME iPhone; UDID from M5; pairing file saved
  5. devmode       lockdownd GetValue; show switch (action 0) or turn on (action 1)
  6. portal        device + App ID (+ App Group) + certificate + profile
  7. sign          sign + verify the IPA
  8. install       installation_proxy over the loopback tunnel
                   (Trust Developer, open the app)
```

`sh barisign` runs it as a web page (a-Shell internal browser sheet over the terminal);
`sh barisign shell` runs the same pipeline in the terminal. Backend and page talk JSON over
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
silence through WebAudio meanwhile (a-Shell has background audio), with the speech loop as
fallback. Terminal line-strain is gone by construction: the flow's stdout goes to the page
log, and only prompts arrive as questions.

## Pairing file

Still written after install via house_arrest so the installed app can refresh itself:
AltStore `Documents/ALTPairingFile.plist`; SideStore `Documents/ALTPairingFile.mobiledevicepairing`
plus `PairingFile_RemoteRP.plist` (newer nightlies read the per-protocol file);
LiveContainer's built-in SideStore the same two names under `SideStore/Documents/`.
The fork plan (`docs/FORK_PLAN.md`) — a pairing step inside our own app builds — stays future
work; the web UI + devmode toggle reduced its urgency, but refresh UX still wants it.
