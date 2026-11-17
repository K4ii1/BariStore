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

So there is no `sh bin/barisign one` that installs on the same device, and we
deliberately do **not** ship one: it would fail at the pairing screen with no
way forward. When only one device is at hand, do everything that does not need
a target (next section), then run `pair` when the second device is back.

### What works with a single device today

| Step | Needs a target? | Command |
|---|---|---|
| Self-check of the pure engine | no | `sh bin/barisign pair --check` |
| Resolve the current release (proves freshness, downloads nothing) | no | part of `sign`: version line first |
| Download the current IPA + size/SHA-256 check | no | `sh bin/barisign sign` (stops cleanly if portal data is missing) |
| Apple sign-in + anisette | no | `sh bin/barisign login` |
| Portal (device/cert/App ID/profile) once a UDID is saved | needs only the saved UDID, not the device in hand | `sh bin/barisign portal` |
| Sign + verify + preflight | no | `sh bin/barisign sign` |
| Install + pairing-file write | **yes, the target** | `sh bin/barisign pair` |

## 2. Background execution — checked against the a-Shell sources

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

## 3. iPad windowed running (the only supported "one screen" setup)

This still needs **two physical devices**; it only puts both windows on one
screen so nothing gets suspended:

1. Open a-Shell, start `sh bin/barisign pair`, leave it visible in half of a
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
