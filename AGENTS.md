# AGENTS.md — BariSign

Project goal: a public GitHub repo that installs **SideStore** (and LiveContainer+SideStore,
AltStore Classic) on an iPhone/iPad **with no computer, on the one device**: a-Shell +
BariSign + LocalDevVPN + Settings. iOS/iPadOS 27+.

## Confirmed decisions (user)

- **Audience = everyone, no computer, one device.** Users sign in with their **main Apple ID**
  (2FA supported); the README must say plainly why that is safe.
- **Single-device flow (2026-11-17 rewrite):** `barisign` opens a web page in a-Shell's
  internal browser and runs requirements → Apple ID → variant → download → pairing →
  Developer Mode → portal → sign → install, all on this iPhone. `barisign shell` is the
  terminal fallback (same order). The two-device plan is deleted.
- **Web UI, not terminal strain:** backend and page talk JSON over 127.0.0.1 with a per-run
  token (siboot's page model). The sheet keeps a-Shell foreground; silence plays while the
  user is in Settings. Terminal output is mirrored to the page log.
- **Developer Mode over the tunnel** (siboot proved it): lockdownd GetValue + AMFI action 0/1
  in clean-room `poc/devmode.py`. No trigger install, no second device.
- **Minimal third-party code:** our engine (pairing/tunnel/install/devmode/web) is MIT from
  MIT `jkcoxson/idevice` protocol sources. `third_party/sideinstaller/` (Apple sign-in + dev
  portal, non-commercial licence, isolated, never copied into MIT files) is the one exception
  left; its clean-room rewrite is future work, not this revision — it would risk breaking login.
- **UDID = pairing only.** This iPhone pairs with itself; the UDID comes back through the
  tunnel. No page, no median flow. `docs/UDID_OPTIONS.md` lists independent UDID sources;
  no permanent server of ours.
- **Shortcuts are suspended** (user decision). No generated `.shortcut` files.
- **Pairing file = a module inside the apps (user decision, 2026-10-29):** still future work
  (see `docs/FORK_PLAN.md`); the installer already writes the pairing file into each app.

- **Device = iOS 27+ only.** iOS 17.4–26.x is out of scope. Stated in `README.md`.
- **Install = pairing + Developer Mode + `installation_proxy`, all on this iPhone, over the
  LocalDevVPN loopback.** AirDrop and OTA are dead for free-profile apps on iOS 27
  (`MIInstallerErrorDomain` 111). Run `barisign`; pair from Settings → Developer →
  Paired Macs on the same iPhone; enter the code.
- **Pure engine (no qh3, no GPL runtime).** `pymobiledevice3` needs `qh3` (native, no iOS
  wheel), so it is not used. The stack is self-contained MIT Python: RPPairing host (SRP-6a,
  TLV8, OPACK), pair-verify, **TLS 1.2 PSK** (0x00AF/0x008C — the suites iOS actually
  negotiates, *not* TLS 1.3), a minimal IPv6/TCP stack, RSD (HTTP/2 + XPC, no HPACK), AFC,
  house_arrest, `installation_proxy`, plus lockdownd GetValue + AMFI actions for Developer
  Mode. No pip, no native wheel. The Linux tests are in `tests/`.
- DNS-SD stays blocked inside a-Shell (`-65555` NoAuth: no `NSBonjourServices` entry), so
  pairing advertises over raw broadcast instead (device-verified M1–M6). The tunnel/install
  engine works on any valid record.
- **Languages:** English only for now; English + Turkish in the final phase, after it works.
- On device and verified: Apple sign-in, the **developer portal** (incl. App Groups), signing,
  and the signed app launching after install. Loopback pairing (M1–M6), the web UI, the
  Developer Mode toggle and the loopback install are written + Linux-tested; the on-device
  run is the remaining gate. Details: `docs/RESULTS.md`, `docs/NEXT_SESSION.md`.
- Download freshness: `resolve()` runs live on every sign (stable tag / nightly asset date
  shown before downloading); cached IPAs reused only on size + SHA-256 match.
- Sign-in requires **Mac-emulating anisette** and the server's own client_info (Apple's Oct 2026
  -80045/-80046/503 rules). `mac-ani.jkcoxson.com` and `ani.jkcoxson.com` come first. Details:
  `docs/ANISETTE.md`, `docs/RESULTS.md`.
- The UI is deliberately terse: one `== STAGE ==` header per screen, one moving line `(2/5) label ....`,
  `ESC[2J ESC[3J` on stage change, `ESC[2K` for the moving line. No long narration.
- Terminal: never change modes more than the password prompt needs (ECHO only, restored and verified);
  the 2FA code is read with our own visible echo so it works even when echo is off.
- Never use GitHub `releases/latest` for SideStore (it returns `0.7.0-alpha`); list releases and
  reject `alpha`/`beta`/`rc` tags.
- **Licence constraint:** code ported from `FrizzleM/SideInstaller` is **isolated** in
  `third_party/sideinstaller/` under its own **non-commercial, source-only** licence (with the
  licence text, attribution and a list of our changes), so the repo as a whole cannot be MIT or
  commercial. Never copy that code into MIT files; prefer reimplementing from MIT sources
  (`nab138/isideload`, `jkcoxson/idevice`). See `THIRD_PARTY_NOTICES.md`.
- **No GPL runtime anymore.** The pure engine is written from the MIT `jkcoxson/idevice` protocol
  sources and Apple's public formats; `pymobiledevice3` is a protocol reference only and is not
  installed by BariSign. Do not copy GPL code into `poc/`.
- Step 1 PoC: `poc/poc_login.py` (MIT) + `third_party/sideinstaller/signin.py` (non-MIT).

## What we are building

Five fixed variants, chosen in the a-Shell menu:

1. SideStore stable
2. SideStore nightly
3. LiveContainer + SideStore stable
4. LiveContainer + SideStore nightly
5. AltStore Classic stable

One flow, five IPAs. **No generic IPA signer.**

The web interface (no Shortcuts, no terminal strain):
- opens a page in a-Shell's internal browser: steps, questions, the pairing PIN, a log;
- runs, always in this order: requirements (LocalDevVPN probe + wait), Apple login (saved
  session reused while Apple accepts it), variant, download, pairing (same iPhone, PIN on
  the page), Developer Mode (tunnel: show or turn on), portal, sign, install;
- anisette failover on -80045/-80046/503; wrong 2FA codes retry without restarting login.

## Hard constraints

- Everything must run on the one iPhone in a-Shell, no computer, no second device.
  - Compute layer: **a-Shell (full)** — stdlib-only Python plus the `cryptography` that ships with it;
    no native binaries, no `openssl`, no `unzip`.
  - The page is stdlib `http.server` on 127.0.0.1 with a per-run token; the sheet is a-Shell's
    internal browser. No dependency, no build step.
- **Never send the Apple ID or password to any remote server we do not control.**
- A **free Apple ID must be enough** (no paid developer account).
- Development runs in a GitHub Codespace (Linux). We **cannot test on an iPhone** — the user
  tests and reports back. Label untested code **untested**; never claim something works without
  the user's on-device confirmation.
- Code, comments, commit messages and the main README are in **English**.
- **Localization**: all user-facing text (script messages, README) lives in
  per-language files so adding a language = adding a file. English first; translations only in
  the final phase, using the cheap model, after asking which languages.
- Interface: the web page (`barisign`), **no Shortcuts** and no generated
  `.shortcut` files. Questions are fields and buttons; the log mirrors the terminal.
  `barisign shell` stays as the terminal fallback. Audio keep-alive must be holdable
  from the page; never add a background mode we cannot hold from Python.

## Variant rules

- Find the **official release sources** for each variant ourselves and verify them.
- Resolve each IPA URL **at runtime**, never hardcode versions. Show the user which version
  they are getting.
- Verify download integrity when checksums exist.
- Warn that nightly builds may be unstable.
- README must document (verified, not from memory) how the variants differ, including free
  Apple ID limits on App IDs and active apps.

## Secrets & safety

- Never commit Apple ID, passwords, pairing files, signing certs or API keys. `.gitignore` them.
- Never print environment variables or secrets, never write them to a file, and check staged
  changes for keys before every commit.
- Ask before destructive commands.
- Respect licenses: keep attribution and license files for ported code; list which licenses
  constrain this repo.

## Budget / process

- Budget ~5 USD total. Be token-frugal: grep/head/tail instead of dumping whole files.
- If the same problem fails twice, **stop** and report so the user can switch to a stronger model.
- Bump `VERSION` in `poc/barisign.py` on every functional commit (0.9.x line; never 1.0.0): the installer title prints
  the version being installed, so the user can see the update arrived.
- Install/update paths: one-line `curl ... install.sh | sh`, plus `barisign update`.
  No `bin/`, no root wrappers: the installer generates `~/Documents/barisign` (launcher).
- Verified on device: sign-in, portal, signing, launch; pairing M1–M6 over raw broadcast.
  Written + Linux-tested, on-device run pending: loopback pairing, web sheet, devmode toggle,
  loopback install. Plan: `docs/PLAN_V2.md`; facts: `docs/RESULTS.md`; handoff:
  `docs/NEXT_SESSION.md`. Pre-rewrite two-device notes live in git history.
- Next: the on-device gates in `docs/NEXT_SESSION.md` (sheet, loopback pairing + keep-alive,
  devmode toggle, install to Trust + open). Report device results; do not expand blind.

## Verified / unverified convention

Anything not confirmed by reading real source or authoritative docs is marked **unverified**.
