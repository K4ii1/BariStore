# Next session — handoff (2026-11-17)

State: version **0.9.23**. Single-device rewrite: `sh barisign` opens a web UI in a-Shell's
internal browser and runs the whole pipeline on this iPhone (requirements → Apple ID →
variant → download → pairing → Developer Mode → portal → sign → install). The two-device
guided flow is deleted; `sh barisign shell` is the terminal fallback (same order, speech
keep-alive). Developer Mode comes over the tunnel now (lockdownd GetValue + AMFI action,
MIT idevice/siboot protocol facts, clean-room code in `poc/devmode.py`): no trigger
install, no second device.

**On-device gates (all UNVERIFIED):**
1. The sheet opens (`BROWSER=internalbrowser openurl`) and stays up during the run.
2. Loopback pairing lists BariSign on the same iPhone; PIN hop + page silence holds us.
3. `devmode show/on` works over the tunnel (status read, switch shown, turn-on path).
4. Install reaches VerifyingApplication and the app opens after Trust.

If a gate fails: send the exact page/terminal text + `state/pair_debug.log`.

## Linux tests (all should pass here)

```
python3 tests/test_protocol.py        # XPC, AFC, RSD, mDNS, OPACK, SRP, SipHash vectors
python3 tests/test_tls_psk.py         # TLS 1.2 PSK interop with OpenSSL, both suites
python3 tests/test_pairing_host.py    # full Pair-Setup round-trip (mock target)
python3 tests/test_pair_tunnel.py     # pair-verify + TLS-PSK + CDTunnel (mock device)
python3 tests/test_tcp6.py            # TCP stack against the Linux kernel through TUN
python3 tests/test_rsd_over_tcp.py    # RSD + AFC 300 KiB + installation_proxy over that stack
python3 tests/test_devmode.py         # devmode status/show/turn-on against fake services
python3 tests/test_webui.py           # page served, token/host guard, Q&A, PIN masking
python3 tests/test_discovery.py       # pairing_target/prefs/registry/export
python3 tests/test_preflight.py       # expiry/UDID/cert/group-stamping
python3 tests/test_custom_ipa.py      # picker
python3 tests/test_loopback.py        # loopback probe + keep-awake no-op
```

## Constraints that still apply

- Everything on the device is pure Python + the shipped `cryptography`; never add a native wheel.
- Keep `sh update` self-updating: `install.sh` must remain the single file it applies.
- Do not name or describe the user's test hardware; say this iPhone.
- Do not claim device success without the user's confirmation. Mark untested code **untested**.
- `third_party/sideinstaller/` stays isolated (non-commercial); never copy it into MIT files.
  The Apple-account + portal clean-room rewrite is still open (see THIRD_PARTY_NOTICES.md):
  do not start it without asking — it risks breaking login.
- Prefer the MIT `jkcoxson/idevice` protocol sources for changes; `pymobiledevice3` is GPL reference
  only and is not installed by BariSign. Do not copy GPL code into `poc/`.
