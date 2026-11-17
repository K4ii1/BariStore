# BariSign

Two iOS/iPadOS devices on the same Wi-Fi are enough. Two roles, no computer:

- **Signer** — runs **a-Shell** and BariSign; signs and installs.
- **Target** — gets the app; uses only Safari and Settings.

Either device can be an **iPhone or an iPad** (iOS/iPadOS 27+). They must be on the **same Wi-Fi**.
a-Shell and BariSign are installed on the **signer only**. One device cannot pair with or
install on itself — see `docs/SINGLE_DEVICE.md` for what works single-device and why.

**Status (0.9.17):** Apple sign-in, the developer portal, signing and launching the signed app are verified on
a real device. Pairing runs over **raw broadcast** (device-verified M1–M6, UDID saved): `DNSServiceRegister`
fails inside a-Shell with `-65555` (no `NSBonjourServices` entry), so `pair` advertises over
broadcast automatically — just run `sh bin/barisign pair` and open Paired Macs on the target. If
that still fails, the engine can install once a pairing record exists:
`pair --import FILE --host <target-ip>` (options in `docs/NEXT_SESSION.md`).

---

## Install (on the signer)

```
mkdir -p ~/Documents/barisign && cd ~/Documents/barisign
curl -sSL "https://github.com/barismd/barisign/blob/main/install.sh?raw=true" -o install.sh
sh install.sh
```

Then one command drives everything (`sh barisign` works the same, shorter):

```
sh barisign            # guided
sh barisign status     # what is saved
```

---

## UDID (pairing only)

The target's UDID comes **from the pairing** — there is no page anymore (removed in 0.9.18).
`udid` pairs by itself:

```
sh barisign udid
```

1. The signer advertises as **BariSign** and prints a code.
2. On the **target**: **Settings → Privacy & Security → Developer Mode → Paired Macs** (or
   **Settings → Developer → Paired Macs**) → **BariSign** → code.
3. The signer reads the UDID from the pairing/tunnel and saves it.

The guided run asks whether Developer Mode is already on the target (Settings > Privacy &
Security > Developer Mode, or Settings > Developer). If it is missing, pairing may still reveal
the switch (Apple documents this); the run then signs and walks you through the trigger: it opens
the signed IPA on the signer, you share it to the target (AirDrop), tap it once on the target,
then delete it from the target. The Developer Mode switch appears after the attempt, and the
install continues. If pairing stays unreachable with no Developer Mode at all, the tool stops —
the UDID page comes back only if Developer Mode cannot be opened with a plain unsigned IPA.
Other UDID sources: `docs/UDID_OPTIONS.md`.

---

## LOGIN (signer)

```
sh bin/barisign login
```

It first proves an anisette server works and Apple answers, then asks for the password (typed as `*`).
`--use-clipboard` takes the password from the clipboard with no typing. `--server URL` pins an anisette
server. A free Apple ID is enough.

---

## PORTAL (signer)

```
sh bin/barisign portal
```

Registers the target's UDID, issues a certificate and downloads a provisioning profile. Verified on a
device: team → device → App ID → certificate → profile, with the target's UDID in the profile.

---

## SIGN (signer)

The guided run does this for you: it resolves the chosen variant's current `.ipa` from the project's own
releases **on every run** (stable: newest non-alpha/beta/rc tag; nightly: the `nightly` tag, versioned by
asset date), prints the version and size **before** downloading, checks the SHA-256 GitHub publishes,
reuses a cached file only when size **and** digest match (`(cached, still current)`), signs it with the key, certificate and profile from the
portal, verifies the result, and writes `<name>-signed.ipa` (plus a `.zip`).

```
sh bin/barisign sign              # download (unless --ipa), sign, zip
sh bin/barisign sign --ipa X.ipa  # sign a file you already have
```

Put a custom IPA in Files > On My iPhone/iPad > a-Shell > Custom IPAs first; the guided
run lists that folder (newest first) as its last menu item and reads the bundle id from the
IPA itself. Downloaded originals live in `barisign/ipa/unsigned/`, signed outputs in
`barisign/ipa/signed/`, so the program folder stays tidy. The portal registers a separate App ID for a custom bundle id
(a free Apple ID has 10 slots), and the install step verifies the embedded profile (expiry +
target UDID) before uploading anything.

---

## INSTALL on the target (signer + target)

> `pair` advertises over raw broadcast automatically — no setup needed. Bonjour stays as a fallback where it works.
> Keep a-Shell in the foreground for the whole run (iPad: Split View / Stage Manager keeps it
> visible); there is no background/Live Activity/Shortcuts path — see `docs/SINGLE_DEVICE.md`.

```
sh bin/barisign pair                       # pick a paired device, or pair a new one
sh bin/barisign pair --loopback          # EXPERIMENTAL: same device via LocalDevVPN (docs/SINGLE_DEVICE.md)
sh bin/barisign pair --export [FILE]       # copy a pairing file out (AirDrop it, or
                                           # import it from the app's own settings)
```

If several devices were paired before, pick one from the list (model + name + UDID);
`pair a new device` pairs another. The sweep finds a moved target by itself; if nothing
answers, answer the retry / re-pair question.

1. If no pairing exists yet, the signer advertises as **BariSign** and prints a 6-digit code.
   Keep the target **unlocked** and on the same Wi-Fi for the whole step.
2. On the **target**, open **Settings → Privacy & Security → Developer Mode → Paired Macs**
   (or **Settings → Developer → Paired Macs**), pick **BariSign**, and enter the code.
3. The signer installs the newest `*-signed.ipa` over Wi-Fi with `installation_proxy`.
4. The signer also writes the pairing file into the installed app:
   AltStore `Documents/ALTPairingFile.plist`; SideStore
   `Documents/ALTPairingFile.mobiledevicepairing` plus `Documents/PairingFile_RemoteRP.plist`
   (newer nightlies read the per-protocol file); LiveContainer's built-in SideStore the same
   two names under `SideStore/Documents/`. A copy stays under `state/` for manual import.
5. On the target, tap **Trust** for the developer and open the app.

There is no separate engine install: `sh install.sh` fetches the program files, and
`sh bin/barisign pair --check` confirms every pure-Python module imports with the `cryptography`
version a-Shell ships. `sh bin/update` updates the same files.

The app installs **only on the target whose UDID is in the profile**: a development-signed app is
refused on any other device or Apple ID. To use another target, register its UDID and sign again.

---

## Free Apple ID limits

- 3 apps installed at a time (SideStore counts as one)
- 10 App IDs
- 7-day signing

---

## Problems

| What you see | What it means |
|---|---|
| `check  fail` | `sh barisign check` prints what broke |
| login `-22406` | Apple says the password is wrong. The Apple ID is case-sensitive here; watch the keyboard's autocorrect. BariSign retries twice and shows the ID it sent |
| login `-80045` / `-80046` / `503` | Apple refused the identity, not the password. It moves to the next anisette server; if all fail, wait 10–15 minutes without retrying |
| UDID not recognised | `40` hex characters, or `24` like `00008110-001a2c3e0e91801e` |
| pairing finds no Paired Macs entry | run plain `sh barisign pair` (raw broadcast is automatic); if the target has no entry after 1 min, restart a-Shell and retry |
| `bin/barisign pair` finds no IPA | sign on the signer first, or pass `--ipa FILE` |
| BariSign does not appear in Paired Macs | run plain `sh bin/barisign pair` (raw broadcast is automatic); if the target has no entry after 1 min, restart a-Shell and retry |
| terminal stops taking input | quit a-Shell from the app switcher and reopen it |
