# BariSign guide — one iPhone, no computer

Everything happens on the **same iPhone**: a-Shell + BariSign, LocalDevVPN, Settings, Safari.
No computer, no second device, no AirDrop, no OTA.

**Status (0.9.23):** the web UI, the loopback install and the Developer Mode toggle are written
and Linux-tested but **UNVERIFIED ON A DEVICE**. Run them and report back: what you saw, plus
`state/pair_debug.log` after any pairing run.

---

## Install (on the iPhone)

```
curl -fsSL https://raw.githubusercontent.com/barismd/barisign/main/install.sh | sh
barisign update   # later: updates everything in place
```

---

## The run

```
barisign
```

A page opens over the terminal. Tap **Start**; answer what it asks. The steps:

1. **Requirements** — LocalDevVPN connected. The page probes
   LocalDevVPN and waits until it answers.
2. **Apple ID** — email, then password (dots), then the 2FA code (6 boxes, sends itself). A saved
   session skips password + 2FA until Apple refuses it.
3. **Portal** — picks your developer team (saved next time, no question).
3. **Pairing** — this iPhone pairs with itself (skipped when a live pairing already
   exists). Settings → Developer → Paired Macs → BariSign, big PIN on the page (if Paired Macs
   is missing, look for a new Developer Mode section — pairing itself can reveal it).
4. **Variant** — tap the app you want, or your own `.ipa` (drop it into Files → a-Shell →
   Custom IPAs first; the picker rescans when the folder was empty).
5. **Download** — the current IPA, with size + SHA-256 checked. Reused when still current.
6. **Developer Mode** — read over the tunnel. If off or hidden: the switch is shown (no restart).
   Turning it on always restarts the iPhone, which ends the run with a restart card: flip it
   (or tap **Turn on now**), let it restart, then open BariSign and tap Start again — everything
   is saved and the run jumps straight back here to verify. With a passcode set, iOS refuses
   the instant path: flip it by hand.
7. **Sign & Install** — registers this iPhone, issues the certificate, downloads the profile
   (with the App Group so SideStore/LiveContainer open their container), signs and verifies
   the IPA, then uploads and installs over loopback. Then: Settings → General → VPN & Device
   Management → trust the developer → open the app.

The page has **Stop** (ends the run anywhere, even mid-upload), **Back** (re-asks the previous
question and replays your answers up to it) and a **Settings** card (version, what is saved,
forget it, update check). If the page ever stops moving, tap Stop and start again — nothing
is half-installed.

`Stop` (or Ctrl-C in the terminal) ends the run any time. Nothing is half-installed.

Prefer the terminal? `barisign shell` runs the same pipeline without the page (same order,
same loopback, speech instead of page audio for keep-alive).

---

## Manual commands

```
barisign status              # what is saved (UDID, variant, release, session)
barisign check               # diagnostics only
barisign login               # Apple sign-in alone
barisign portal              # device + certificate + profile alone
barisign sign                # download + sign alone
barisign pair --devmode status|show|on
                                # Developer Mode alone (status default in install)
barisign forget              # clear the saved state
barisign reset               # remove saved state, IPAs and zips
```

---

## Free Apple ID limits

- 3 apps installed at a time (SideStore counts as one)
- 10 App IDs
- 7-day signing (SideStore renews itself on-device with the pairing file we write into it)

---

## Problems

| What you see | What it means |
|---|---|
| `check  fail` | `barisign check` prints what broke |
| sheet does not open | run `BROWSER=internalbrowser openurl <the printed URL>` by hand |
| LocalDevVPN never answers | connect it (tunnel must be ON, not just installed) |
| login `-22406` | Apple says the password is wrong. BariSign retries twice |
| login `-80045` / `-80046` / `503` | Apple refused the identity, not the password. It moves to the next anisette server; if all fail, wait 10–15 minutes |
| 2FA code rejected | enter the current code; after 3 misses the login restarts (password kept) |
| BariSign missing in Paired Macs | same iPhone? LocalDevVPN connected? restart a-Shell and retry |
| Developer Mode still off | flip it in Settings, let the iPhone restart, continue on the page |
| `pair` finds no IPA | sign first, or pass `--ipa FILE` |
