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
sh barisign update   # later: updates everything in place
```

---

## The run

```
sh barisign
```

A page opens over the terminal. Tap **Start**; answer what it asks. The steps:

1. **Requirements** — LocalDevVPN connected, volume audible. The page probes
   LocalDevVPN and waits until it answers. Developer Mode is checked later over the
   tunnel: if off, the switch is shown (or turned on) before signing.
2. **Apple ID** — email, then password (dots), then the 2FA code (6 boxes, sends itself). A saved
   session skips password + 2FA until Apple refuses it.
3. **Variant** — 1–5, or 6 for your own `.ipa` (drop it into Files → a-Shell → Custom IPAs first;
   the picker rescans when the folder was empty).
4. **Download** — the current IPA, with size + SHA-256 checked. Reused when still current.
5. **Pairing** — open Settings → Developer → Paired Macs → BariSign, enter the big PIN. The page
   plays silence so iOS holds the app while you are in Settings.
6. **Developer Mode** — read over the tunnel. If off or hidden: the switch is shown (no restart);
   either flip it in Settings (restart, come back) or tap **Turn on now** (restarts at once; needs
   no passcode — with a passcode set, iOS refuses and you flip it by hand).
7. **Portal** — registers this iPhone, issues the certificate, downloads the profile (with the App
   Group so SideStore/LiveContainer open their container).
8. **Sign** — signs and verifies the IPA.
9. **Install** — uploads and installs over loopback. Then: Settings → General → VPN & Device
   Management → trust the developer → open the app.

`Stop` (or Ctrl-C in the terminal) ends the run any time. Nothing is half-installed.

Prefer the terminal? `sh barisign shell` runs the same pipeline without the page (same order,
same loopback, speech instead of page audio for keep-alive).

---

## Manual commands

```
sh barisign status              # what is saved (UDID, variant, release, session)
sh barisign check               # diagnostics only
sh barisign login               # Apple sign-in alone
sh barisign portal              # device + certificate + profile alone
sh barisign sign                # download + sign alone
sh barisign pair --devmode status|show|on
                                # Developer Mode alone (status default in install)
sh barisign forget              # clear the saved state
sh barisign reset               # remove saved state, IPAs and zips
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
| `check  fail` | `sh barisign check` prints what broke |
| sheet does not open | run `BROWSER=internalbrowser openurl <the printed URL>` by hand |
| LocalDevVPN never answers | connect it (tunnel must be ON, not just installed) |
| login `-22406` | Apple says the password is wrong. BariSign retries twice |
| login `-80045` / `-80046` / `503` | Apple refused the identity, not the password. It moves to the next anisette server; if all fail, wait 10–15 minutes |
| 2FA code rejected | enter the current code; after 3 misses the login restarts (password kept) |
| BariSign missing in Paired Macs | same iPhone? LocalDevVPN connected? restart a-Shell and retry |
| Developer Mode still off | flip it in Settings, let the iPhone restart, continue on the page |
| `pair` finds no IPA | sign first, or pass `--ipa FILE` |
