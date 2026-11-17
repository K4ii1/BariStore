# Web UI — how `poc/webui.py` works

`barisign` with no arguments runs this, not the terminal flow. One file, stdlib only
(`http.server` + `threading`); no build step, no assets except `../barisign.svg`.

## Server model

- `run()` picks a random port on **127.0.0.1 only**, mints a 128-bit hex token, and
  serves everything under `/<token>/…`. Any other path → 404. Requests whose `Host`
  is not `127.0.0.1:<port>` (or `localhost:<port>`) are rejected — no DNS rebinding,
  no LAN snooping, no website probing a loopback port can guess the path.
- It opens a-Shell's internal browser sheet with
  `BROWSER=internalbrowser openurl http://127.0.0.1:<port>/<token>/`
  (same pattern as siboot's page). If the sheet does not open, the terminal prints
  the URL and the manual command.
- Closing the sheet ends nothing by itself. The run ends on **Stop**, on Ctrl-C,
  on error, or on Done (then Enter in the terminal, or a 10-minute cap), and the
  server shuts down with it. Per-run token means nothing survives the process.

## HTTP API (all JSON unless a plain form POSTs, which gets a 303 redirect)

| Endpoint | Direction | Purpose |
|---|---|---|
| `GET /<token>/` | → page | server-rendered HTML (works with scripts off) |
| `GET /<token>/api/state` | → JSON | steps, activity, progress, pin, question, log tail, keepalive, rev |
| `GET /<token>/api/panel` | → JSON | main-card `{rev, title, body}` for in-place swaps |
| `POST /<token>/api/start` | ← | start the flow once |
| `POST /<token>/api/answer` | ← | `{id, value}` answers the pending question |
| `POST /<token>/api/back` | ← | re-ask the previous question (replay mode) |
| `POST /<token>/api/stop` | ← | stop now; also cancels in-flight waits |
| `POST /<token>/api/audio` | ← | page confirms silent audio is playing |
| `POST /<token>/api/update` | ← | run `barisign update` in a thread, report in Settings |
| `POST /<token>/api/forget` | ← | delete saved state, then require a restart |
| `POST /<token>/api/export` | ← | copy the pairing file to `~/Documents/BariSign-Pairing.plist` |
| `GET /<token>/icon.svg` | → file | repo-root `barisign.svg` (favicon + header, rounded via CSS) |

## Shared state (`_STATE`, guarded by `_LOCK`)

`steps[]` (`todo|active|done|error`), `activity` (one clean line, never raw terminal),
`progress` (0–100 or None), `pin`, `question` (`{id, kind, label, options}`, kinds:
`text|secret|code|bool|choice`), `log` (last 200, PIN masked), `done`, `audio`
(page playing silent audio), `keepalive` (text shown next to keep-alive),
`update_msg` / `export_msg` (Settings panel), `started`, `rev` (bumped on every
question/pin/done change; the page re-renders the card only when it moves).

## Flow order (fixed, both UIs)

requirements → Apple ID → portal (team pick) → pairing → variant → download →
Developer Mode → sign & install. Portal needs only the team (no UDID, no bundle),
pairing is skipped when a fresh record exists (`paired_at` < 30 min → "one PIN per
run"), and the App ID/profile download happens inside sign & install where the
bundle id is known. Terminal (`barisign shell`) runs the same order.

## How the backend drives the page

- One flow thread runs `_flow()` with `sys.stdout` replaced by `_WebLog`, which
  strips ANSI, drops spinner chatter (`(1/2) …` lines never become the status),
  extracts `NN%` for the bar, catches `pairing code: DIGITS` into `state["pin"]`
  (masked in the log), and appends everything else to the log.
- Every blocking prompt is replaced: `_ask`/`_yes`/`_read_line`/`_portal_ask` /
  `_portal_confirm` (barisign), `_read_password` (poc_login), `_ask`/`_read_line`
  (pair_install), plus `pick_team` (renders real team buttons). The terminal behind
  the sheet goes quiet; the page is the whole interface.
- Pairing and install run **in-process** (`pair_install._run` via `run_coro`,
  which keeps a cancellable task handle so Stop works mid-wait). The UDID page
  and `--manual`/`--page` are deleted; there is no subprocess and no pasted UDID.
- `_ask_web` kinds: `text`, `secret` (dots), `code` (numeric, autosends at 6
  digits), `bool` (Yes/No), `choice` (one button per option). Codes are never logged.

## Back button (replay)

`_HISTORY` records every answered question in order. Back arms `_REPLAY` mode and
wakes the pending prompt with a `__back__` sentinel, which raises `FlowRestart`;
`_run_flow` resets the steps and reruns `_flow`, auto-answering saved questions
until the last one, which is asked again for editing. A changed answer that no
longer matches the replayed question stops the replay and continues fresh.

## Keep-alive (no sound, by decision)

- Page: looping silent WebAudio buffer started on the Start tap, re-requested on
  every poll, plus a Wake Lock request; the keep-alive indicator shows the state.
- If the page never confirms audio, there is **no speech fallback** in the web
  flow — the page says to keep the app open with the screen awake. (The terminal
  fallback keeps its own `--keep-awake` speech loop.)
- No-JS fallback: server-rendered page + meta refresh only while waiting (never
  while typing), plain forms, always-visible log, no audio path.

## Developer Mode inside the flow

`_devmode_web` opens the tunnel itself, reads status, and on off/hidden runs
`action 0` (show switch, no restart). Turning it **on** always restarts the
iPhone, which kills the run — so the flow shows a restart card and stops; the
rerun jumps straight back (UDID, pairing, download, portal data are saved).
With a passcode set, iOS refuses action 1 and the user flips the switch by hand.

## Settings panel

Rendered server-side on every rev bump: BariSign version, saved Apple ID / UDID /
pairing age / portal session, update result, export result, and three buttons:
Check for updates (`/api/update` → `barisign update` in a thread, then restart
to use it), Export pairing file, Forget saved state (clears state, then requires
a restart). Log collapses with a toggle button that survives polling.

## Testing it here

`tests/test_webui.py` covers: page render in every state (start/question/pin/done),
token + Host guard (wrong token/host → 404), Q&A round-trip, Back arming, Stop
cancelling an in-flight wait, settings/export endpoints, PIN capture + masking,
`/api/panel` rev behavior. It never touches the network or the real state dir.
