# Pairing + Developer Mode + `installation_proxy` — over loopback

Single-device build (0.9.23): everything below runs against `10.7.0.1` (LocalDevVPN)
instead of a second device's Wi-Fi address. The protocol is unchanged; only the
transport's far end moved onto this iPhone.

## The route, as built

1. **Pairing host.** `poc/pairing.py` advertises `_remotepairing-pairable-host._tcp`
   over raw broadcast (a-Shell cannot use DNS-SD: `-65555`). This iPhone lists BariSign
   under **Settings → Developer → Paired Macs**; entering the PIN completes Apple
   Pair-Setup M1–M6 (SRP-6a, TLV8, ChaCha20-Poly1305, OPACK). The UDID arrives in M5.
   The record is saved in `state/` (`PairingFile_RemoteRP.plist`, `ALTPairingFile.plist`,
   `ALTPairingFile.mobiledevicepairing`) and written into the installed app later.
2. **Tunnel.** `poc/rpp_tunnel.py` runs pair-verify, `createListener`, and a **TLS 1.2 PSK**
   tunnel (`0x00AF`/`0x008C`) to the loopback port, then a minimal userspace IPv6/TCP
   stack (`poc/tcp6.py`) carries RSD (`poc/remote_xpc.py`: HTTP/2 + XPC, no HPACK).
3. **Developer Mode.** `poc/devmode.py`: lockdownd `GetValue` (`DeveloperModeStatus` /
   `com.apple.security.mac.amfi`); AMFI `{"action": 0}` shows the switch, `{"action": 1}`
   turns it on (restart; refused with a passcode set — then show + flip by hand).
   `pair --devmode status|show|on` runs each step alone; the install checks automatically
   (`--no-devmode` skips).
4. **Install.** `installation_proxy` installs the staged IPA as a developer package
   (`PackageType: "Developer"`); house_arrest writes the pairing file into the app.
   Preflight (embedded profile expiry/UDID/cert) runs before the 40 MB upload.

No pip process, no engine download, no native wheel, no GPL runtime. Linux tests for each
layer are in `tests/`; the loopback device run is the remaining gate
(`docs/NEXT_SESSION.md`).

## Discovery, as it stands

Loopback needs no discovery: host is `10.7.0.1`, port is probed (49152, then a short
scan; `--loopback-port` pins it). The Wi-Fi path (`--host IP`, sweep, registry menu)
remains in the code for debugging but is out of the documented flow.

## Pairing file

Written after install via house_arrest; if the app is not installed yet the step is
skipped and the copies in `state/` remain for manual import.
