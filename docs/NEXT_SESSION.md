# Next session — handoff

State: version **0.9.31**. One-line install (`curl ... install.sh | sh`) into
`~/Documents/barisign` (launcher, no `cd` needed) + `barisign_files/`;
`barisign update` self-updates in place (python compare, "all current" when nothing
changed; no `cmp`, no `bin/`, no `sh` prefix anywhere user-facing). `barisign`
opens a web UI in a-Shell's internal browser and runs the whole pipeline on this
iPhone: requirements → Apple ID → portal (team pick) → pairing (PIN; skipped when
fresh, retry loop on timeout) → variant (tap-to-choose incl. custom IPA) →
download → Developer Mode (tunnel show/instant-turn-on; restart ends the run with
a restart card, rerun resumes) → sign & install. `barisign shell` is the terminal
fallback (same order). Page: server-rendered + JS DOM patching, silent WebAudio
keep-alive (no speech anywhere), Back (replay answers), Stop (cancels in-flight
waits), collapsible log, Settings card (version, saved state, update check,
pairing-file export, forget). Icon: repo-root `barisign.svg`, served at
`/icon.svg`, favicon + header (rounded via CSS). `barisign udid` is gone
(internal pairing only); `barisign netcheck` diagnoses DNS/TLS/HTTP per anisette host.

**On-device gates (all UNVERIFIED):**
1. The sheet opens (`BROWSER=internalbrowser openurl`) and stays up during the run.
2. Loopback pairing lists BariSign on the same iPhone; PIN hop + page audio holds us.
3. `devmode show/on` works over the tunnel (status read, switch shown, turn-on path).
4. Install reaches VerifyingApplication and the app opens after Trust.
5. Report-back path: exact page/terminal text + `state/pair_debug.log`
   (+ `barisign netcheck` output for sign-in failures).

## Linux tests (all should pass here)

```
python3 tests/test_protocol.py        # XPC, AFC, RSD, mDNS, OPACK, SRP, SipHash vectors
python3 tests/test_tls_psk.py         # TLS 1.2 PSK interop with OpenSSL, both suites
python3 tests/test_pairing_host.py    # full Pair-Setup round-trip (mock target)
python3 tests/test_pair_tunnel.py     # pair-verify + TLS-PSK + CDTunnel (mock device)
python3 tests/test_tcp6.py            # TCP stack against the Linux kernel through TUN
python3 tests/test_rsd_over_tcp.py    # RSD + AFC 300 KiB + installation_proxy over that stack
python3 tests/test_devmode.py         # devmode status/show/turn-on against fake services
python3 tests/test_webui.py           # page/panel/forms in every state, guards, Q&A, Back, Stop-cancel, PIN masking, settings, export, icon
python3 tests/test_discovery.py       # pairing_target/prefs/registry/export
python3 tests/test_preflight.py       # expiry/UDID/cert/group-stamping
python3 tests/test_custom_ipa.py      # picker
python3 tests/test_loopback.py        # loopback probe + keep-awake no-op
```

## Constraints that still apply

- Everything on the device is pure Python + the shipped `cryptography`; never add a native wheel.
- Keep `barisign update` self-updating: `install.sh` must remain the single file it applies.
- Do not name or describe the user's test hardware; say this iPhone.
- Do not claim device success without the user's confirmation. Mark untested code **untested**.
- `third_party/sideinstaller/` stays isolated (non-commercial); never copy it into MIT files.
  The Apple-account + portal clean-room rewrite is still open (see THIRD_PARTY_NOTICES.md):
  do not start it without asking — it would risk breaking login.
- The web UI contract lives in `docs/WEB_UI.md` (endpoints, state, patching, Back/Stop).
- Prefer the MIT `jkcoxson/idevice` protocol sources for changes; `pymobiledevice3` is GPL reference
  only and is not installed by BariSign. Do not copy GPL code into `poc/`.
