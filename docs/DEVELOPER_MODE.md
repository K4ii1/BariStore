# Developer Mode — over the tunnel, no trigger install

The old trigger (share a signed IPA, tap it, delete it) is gone. Developer Mode is read
and requested through the same pairing + tunnel as the install:

```
sh barisign pair --devmode status   # on / off / unknown  (default in the flow)
sh barisign pair --devmode show     # reveal the switch in Settings (no restart)
sh barisign pair --devmode on       # turn it on now (restarts; asks first)
```

Mechanics (MIT sources, clean-room code in `poc/devmode.py`):

- lockdownd answers `GetValue` with `Key=DeveloperModeStatus`,
  `Domain=com.apple.security.mac.amfi` (the same read pymobiledevice3 does).
- AMFI's RSD shim (`com.apple.amfi.lockdown.shim.remote`) takes `{"action": 0}`
  to show the switch and `{"action": 1}` to turn it on (the same calls MIT
  idevice implements; siboot documents the whole flow). The reply carries
  `success` or `Error`; iOS closes AMFI after one request.
- With a passcode set, turn-on is refused (`Device has a passcode set`): show the
  switch and flip it by hand. Without one, the iPhone restarts — the tunnel dies
  with it, so the flow re-opens and re-checks after you come back.

It only helps while the iPhone still answers on its pairing port with this pairing:
pair first, then devmode, then the rest. If the service names are missing from the
RSD map, the error lists what the device offers — send that back.
