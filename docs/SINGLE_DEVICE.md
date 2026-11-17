# Single device, background and version checks — what is possible (2026-11-17)

This note answers three questions from the same test run: can one device do the
whole flow with LocalDevVPN, can a-Shell keep the pairing server alive in the
background (Live Activity / notification / Shortcuts), is the downloaded IPA
proven current at every signing, and how should an iPad be held while testing.

Sources are the a-Shell sources themselves (`holzschu/a-Shell`, `Info.plist`,
`a-Shell-Intents/`, `*.swift`), not guesses.

## 1. One device cannot pair with and install on itself (stock iOS)

The two roles are not a UI choice; iOS enforces them:

- Pairing is **device-initiated**. The target's **Settings → Developer →
  Paired Macs** lists *remote* hosts. The same device cannot list itself as a
  pairable Mac, so M1–M6 can never run against loopback.
- The install path needs the **target's lockdownd** over the network
  (`_remotepairing` → RSD → `installation_proxy`). Connecting to your own
  lockdownd from the sandbox is not exposed, and a free-provisioned app cannot
  be installed from the device onto itself (the same policy that refuses
  AirDrop/OTA installs of free-profile IPAs on iOS 27, `MIInstallerErrorDomain`
  111, applies here).
- **LocalDevVPN does not change this.** It is a loopback packet tunnel that
  gives an app a path to the phone's *own* developer services (`10.7.0.1`) for
  install/refresh traffic. It does not make the device appear in its own
  Paired Macs list, does not issue a pairing record, and does not turn the
  device into a pairing host for itself. See `docs/DEVELOPER_MODE.md`.

So there is no `sh barisign one` that installs on the same device by default — but
since 0.9.19 there is an **experimental** attempt path: `sh barisign pair --loopback`
(++`--pair-only` first to test without installing). It reuses the whole tunnel/install
engine unchanged against the LocalDevVPN loopback (`10.7.0.1`, port probed) instead of the
Wi-Fi target, and `--keep-awake` loops speech to hold the process while you enter the PIN
in Settings. What it still cannot do: make the *same phone's* Settings list us (unverified —
check with your eyes whether BariSign appears in Paired Macs on the same device), and no
script can *guarantee* background survival. Full experiment steps in §5.

### What works with a single device today

| Step | Needs a target? | Command |
|---|---|---|
| Self-check of the pure engine | no | `sh barisign pair --check` |
| Resolve the current release (proves freshness, downloads nothing) | no | part of `sign`: version line first |
| Download the current IPA + size/SHA-256 check | no | `sh barisign sign` (stops cleanly if portal data is missing) |
| Apple sign-in + anisette | no | `sh barisign login` |
| Portal (device/cert/App ID/profile) once a UDID is saved | needs only the saved UDID, not the device in hand | `sh barisign portal` |
| Sign + verify + preflight | no | `sh barisign sign` |
| Install + pairing-file write | **yes, the target** | `sh barisign pair` |
| Same-device experiment (LocalDevVPN loopback) | **experimental, §5** | `sh barisign pair --loopback --pair-only` first |

## 2. Background execution — checked against the a-Shell sources (2026-11-17)

BariSign is a **guest inside a-Shell**: Python scripts running in another app's sandbox, under
another app's signed `Info.plist` and entitlements. Anything that needs a new entitlement, a new
background mode, a new `NSBonjourServices` entry or native Swift code cannot be added from our
side — it would mean rebuilding a-Shell itself, which is not our app.

| Idea | Verdict | Why |
|---|---|---|
| Live Activity | **not possible** | No `ActivityKit` / `ActivityConfiguration` anywhere in `a-Shell/`; adding one needs a rebuilt app with a new entitlement, which is outside this repo. |
| Local notification to keep the server alive | **not possible** | No `UNUserNotificationCenter` scheduling in `a-Shell/`; the `remote-notification` background mode in `Info.plist` does nothing without a push server, and a notification alone would not keep a Python socket server running anyway. |
| `audio` background mode as keep-alive | **not usable from our code** | `Info.plist` lists `audio`, but the source only configures audio for playback (`AppDelegate`/`SceneDelegate`); there is no silent-audio API exposed to Python, and abusing it would risk the App Store listing a-Shell depends on. |
| Shortcuts running `pair` in the background | **not viable** | The intents extension exposes exactly three intents (`ExecuteCommand`, `GetFile`, `PutFile`). Python is **not** in the `localCommands` list, so any `pair`/`sign` command forces `openWindow = .open` (the app comes to front). Even a lightweight command is time-boxed by Shortcuts and cannot host a minutes-long pairing broadcast + tunnel. This is also why Shortcuts stay suspended (user decision, `AGENTS.md`). |
| `fetch` background mode | **not usable** | Declared in `Info.plist`, but there is no hook that would run our Python during a fetch wake, and the window (~30 s) is far too short for pairing + 30 MB install. |

Practical consequence: **keep a-Shell in the foreground** for the whole `pair`
run, and keep the target unlocked on the same Wi-Fi. On iPad use Split View or
Stage Manager (next section) — that is a foreground-management trick, not
background execution.

### Why SideInstaller can do it on-device and we cannot (yet)

SideInstaller's iOS app (Madeira) pairs and installs **from the same phone**: its own
`PairingController.swift` runs an RPPairing host, **keeps the app alive with silent audio**
(SideInstaller NOTES: "works iOS 17.4+"), and talks to the phone's own lockdownd over a
**LocalDevVPN-loopback** connection. Every piece of that is a *native-app* capability:

| Piece | SideInstaller (native app, own entitlements) | BariSign (Python guest in a-Shell) |
|---|---|---|
| Silent-audio keep-alive | its own `audio` background mode + `AVAudioSession` in Swift | a-Shell's `audio` mode exists but exposes **no** playback API to Python (`say` is speech, `ffmpeg` is file conversion); we cannot start an audio session from a script |
| Loopback lockdown via LocalDevVPN | its own code connects to `10.7.0.1` | a TCP connect to `10.7.0.1` from Python needs no special entitlement and may work — but it is useless without the pairing first, see next row |
| Being pairable by the same phone | the app advertises itself through its own stack with its own `Info.plist` | our host runs inside a-Shell: no `NSBonjourServices` entry (proven `-65555`), so the *same phone's* Settings cannot discover us either |
| Showing the PIN | its own screen | our terminal — only visible while a-Shell is foreground |

So "they do on-device pairing, why can't we" has a real answer: they are an app, we are a
script inside somebody else's app. Replicating their loop means becoming an app too — which
is exactly what the fork plan (`docs/FORK_PLAN.md`) is: the pairing module with silent audio
goes into *our* builds of SideStore/LiveContainer/AltStore, where we own the entitlements.
Writing a silent-audio hack in Python (a `say` loop, a notification) would not hold the
pairing socket open and would only burn the test budget. No code was added for this: the
decision is documented, not implemented.

## 3. iPad windowed running (the only supported "one screen" setup)

This still needs **two physical devices**; it only puts both windows on one
screen so nothing gets suspended:

1. Open a-Shell, start `sh barisign pair`, leave it visible in half of a
   Split View (or a Stage Manager window).
2. Keep Safari/Settings on the *other* device for the target steps — the iPad
   window trick does not replace the target.
3. If a-Shell ever leaves the foreground, assume the advertisement stopped:
   rerun `pair` (the registry keeps the record, `--repair` only if the target
   stops offering a prompt).

Do not lock the signer mid-run; iOS suspends the Python process within seconds
and the target's prompt times out.

## 4. The downloaded IPA is proven current at every signing

`poc/download.py` (`resolve` + `ensure`, rules in `variants.json`):

1. **Every** `sign`/guided run calls `resolve()`, which lists
   `https://api.github.com/repos/{repo}/releases?per_page=30` live — nothing
   is pinned. Stable = newest release with no `alpha`/`beta`/`rc` in the tag
   (never `/releases/latest`: SideStore's is `0.7.0-alpha`); nightly = the
   release tagged exactly `nightly`, versioned by the **asset's**
   `updated_at` (its `published_at` is stale); AltStore matches by asset
   pattern because the version is in the filename.
2. The run prints the resolved version **before** downloading
   (`SideStore 0.6.0 (24.1 MB)` / `LiveContainer+SideStore nightly
   2026-11-12 (23.8 MB)`), and after `ensure()` prints
   `(cached, still current)` only when the file on disk matches **both** the
   size and GitHub's SHA-256 digest. Any newer release changes size/digest,
   so a stale cache can never pass as current.
3. `status` keeps the last resolved string (`release` row) from
   `state/asset_version`.
4. Offline fallback: if GitHub is unreachable but a previous IPA exists, the
   run says so explicitly (`<name> (no GitHub; using the saved file)`) and
   records `saved file` — it never claims to be current.

Linux-side, `tests/` covers the resolver rules; the live GitHub call itself
is exercised by every real `sign` run.

## 5. The loopback experiment (0.9.19, UNVERIFIED on a device)

Prerequisites on the one device: **LocalDevVPN installed and connected**, a-Shell foreground,
volume audible (the keep-alive speaks). Then:

```
sh barisign pair --loopback --pair-only --keep-awake
```

1. The signer advertises as **BariSign** (raw broadcast, as usual). Open **Settings ->
   Developer -> Paired Macs on the SAME device** and look: if BariSign is listed, the same
   phone can see our broadcast and pairing can proceed — enter the printed PIN.
2. With a record, the tool probes `10.7.0.1` (explicit `--loopback-port P` wins, else 49152,
   else a short scan) and runs pair-verify + tunnel + RSD over loopback — the same code as
   the Wi-Fi path. `--pair-only` stops after the UDID check: **send back** the UDID line or
   the exact error line plus `state/pair_debug.log`.
3. If it pairs, drop `--pair-only` to install the newest `-signed.ipa` on the same device.

Report these three separately: (a) same-device Paired Macs lists BariSign yes/no, (b) the
loopback port that answered (or the LocalDevVPN error), (c) whether `--keep-awake` held us
while you typed the PIN. Any `no` stops the experiment — that answer is the result.
