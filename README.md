# BariSign

Install **SideStore** — or **LiveContainer + SideStore**, or **AltStore Classic** — on an iPhone or iPad
**with no computer**, using your own free Apple ID. The design needs **two iOS/iPadOS devices on the
same Wi-Fi**: a signer (a-Shell) and a target (Safari + Settings).

> **Pairing works from a-Shell via raw broadcast.** iOS only allows Bonjour types listed in an
> app's signed `NSBonjourServices` allowlist, so a-Shell's `DNSServiceRegister` call fails with
> `-65555` — but BariSign announces `_remotepairing-pairable-host._tcp` over raw multicast/broadcast
> instead, no setup needed: run `sh bin/barisign pair` and open Paired Macs on the target. The
> **signing/portal/UDID-page** path and the **pure tunnel/install engine** are unaffected.
> Details and fallbacks (`--host`, `--import`): `docs/NEXT_SESSION.md`.

| Role | What it is | What it runs |
|---|---|---|
| **Signer** | the device that signs and installs | **a-Shell** + BariSign |
| **Target** | the device that gets the app | Safari + Settings only |

Both devices may be an **iPhone or an iPad**; iOS and iPadOS both work. The role is chosen at run time.
They must be on the **same Wi-Fi**. The target never installs a-Shell or BariSign.

> **Status (0.9.17):** verified on a real device running iOS 27: Apple sign-in, the developer portal,
> signing, launching the signed app — and device-initiated pairing (M1–M6, UDID saved). The pure
> tunnel/install engine is Linux-tested end to end; the on-device install is next. One device
> cannot do the whole flow (see `docs/SINGLE_DEVICE.md`); keep a-Shell foreground for `pair`.

---

## How the flow works

1. On the **signer**, install a-Shell and BariSign, then run `sh bin/barisign`.
2. Sign in with your Apple ID. On the **target**, check Settings → Developer Mode:
   if the switch is missing, the guided run walks you through a one-time trigger
   install that makes it appear.
3. Pair the target: on the **target** open Settings → Developer Mode (or Settings →
   Developer) → Paired Macs, pick **BariSign**, enter the code. The signer takes the
   target's **UDID from the pairing** and continues; there is no UDID page anymore.
4. Pick the variant, then the signer downloads its **original** IPA, registers the
   target in the developer portal (device + App ID + certificate + profile), and signs.
5. Install over Wi-Fi with `installation_proxy`. The pairing file is saved under
   `state/` and written into the installed app (AltStore `Documents/ALTPairingFile.plist`;
   SideStore `Documents/ALTPairingFile.mobiledevicepairing` plus `PairingFile_RemoteRP.plist`;
   LiveContainer's built-in SideStore the same two names under `SideStore/Documents/`)
   so the installed app can refresh itself.
6. On the target, trust the developer and open the app.

> **How the install works:** a pairing record (made by pairing once from Settings) opens
> the target's `_remotepairing` service over Wi-Fi. A pure TLS 1.2 PSK tunnel carries a small
> userspace TCP stack; `installation_proxy` installs the staged IPA as a developer package, and
> house_arrest writes the pairing file into the app. The target only trusts the developer and
> opens the app. Device-tested through pairing; the install step is next in line for a device run.

If pairing cannot produce a UDID (old target, Developer Mode not available), there is
currently no fallback in the tool — the signer-hosted UDID page was removed in 0.9.18.
If Developer Mode cannot be opened with a plain unsigned IPA, the page comes back.

---

## What works

| | |
|---|---|
| **Apple sign-in** (free ID, 2FA) | ✅ verified |
| **Device, certificate, profile** (developer portal) | ✅ verified |
| **Download + sign + verify** | ✅ verified — the signed IPA installs and the app launches on a device |
| **UDID from pairing** (pair-first) | ✅ verified on a device |
| **Signer → target pairing install** (`sh barisign pair`) | ⚠️ engine + discovery ready; on-device install is next |
| **Two devices, no computer** | the design; pairing proven, install pending a device run |

---

## Get it — on the signer only

In a-Shell on the **signer**:

```
mkdir -p ~/Documents/barisign && cd ~/Documents/barisign
curl -sSL "https://github.com/barismd/barisign/blob/main/install.sh?raw=true" -o install.sh
sh install.sh
```

`sh bin/update` self-updates everything in one command: it reads the newest `install.sh` from the
repository and applies it (files and `bin/update` itself). Your saved state in `state/` is kept.
There is **no engine download and no pip step**: the pairing engine is part of the program files.

```
sh barisign          # guided: check -> Apple ID -> devmode -> pairing/UDID -> variant -> download -> portal -> sign -> install
sh barisign pair     # pair the target and install over Wi-Fi
sh barisign status   # what is already known
sh barisign --help   # every command
```

`sh barisign` is the same program as `sh bin/barisign`, only shorter. Updates stay
`sh bin/update` and `sh install.sh`.

---

## Requirements

| | |
|---|---|
| **Both devices** | iOS/iPadOS **27 or newer** |
| Apple account | a **free** Apple ID — no paid Developer Program membership |
| **Signer** | **a-Shell** (free, App Store) — BariSign runs here |
| **Target** | no extra app; Safari and Settings only |
| Computer | **none** — signing and the Wi-Fi install are designed to run entirely on the signer |
| Network | both devices on the same **Wi-Fi**; internet for Apple and the IPA download |
| On the target | LocalDevVPN for SideStore to refresh apps after install |

---

## The UDID, in one paragraph

A free Apple ID signs apps for **specific devices**, so the **target's UDID** must be known. The **pairing gives the UDID**: the signer runs the pairing host, the target pairs from Settings, and
the signer reads the target's UDID from the pairing/tunnel. There is no UDID page anymore (removed
in 0.9.18); `docs/UDID_OPTIONS.md` lists independent UDID sources (not affiliated with us).

---

## Which variant you get

| # | Variant | Source |
|---|---|---|
| 1 | **SideStore** (stable) | `SideStore/SideStore` |
| 2 | **SideStore** (nightly — *may be unstable*) | `SideStore/SideStore`, tag `nightly` |
| 3 | **LiveContainer + SideStore** (stable) | `LiveContainer/LiveContainer` |
| 4 | **LiveContainer + SideStore** (nightly) | `LiveContainer/LiveContainer`, tag `nightly` |
| 5 | **AltStore Classic** (stable) | `altstoreio/AltStore` |
| 6 | **Custom IPA** (your own file, already on the signer) | your file; pick `custom IPA file` in the guided run, or `sign --ipa FILE` |

Every version is resolved **at runtime** from the project's official release page — never pinned here —
and you are shown which version you are about to get (stable: the tag; nightly: the asset date,
because its `published_at` is stale). A cached IPA is reused only when size **and** GitHub's SHA-256
match; offline runs say `(no GitHub; using the saved file)`. `variants.json` is the machine-readable list.
Single-device limits, background execution and iPad windowing: `docs/SINGLE_DEVICE.md`.

---

## Your Apple ID and your data

- **Your password is never transmitted.** Apple's sign-in is SRP-6a: the password becomes a one-time proof
  on the signer. It is never written to disk.
- **The anisette server never sees your account.** It is asked only for device-identity headers, with a
  random identifier we generate — never your Apple ID, password or token.
- **No BariSign server exists.** Nothing is collected: no analytics, no telemetry, no accounts.
- TLS verification is never disabled anywhere in this project.

---

## Documentation

| File | What it is |
|---|---|
| **`GUIDE.md`** | step-by-step, in plain language |
| `docs/PAIRING_INSTALL.md` | how the signer pairs with and installs on the target |
| `docs/UDID_OPTIONS.md` | UDID sources (pairing only; page removed in 0.9.18) |
| `docs/ANISETTE.md` | anisette servers: what they see, which ones we use, how to pin or self-host |
| `docs/PLAN_V2.md` | the current architecture and why |
| `docs/FORK_PLAN.md` | the pairing module inside the forked apps: licences, CI, risks |
| `docs/RESULTS.md` | what is verified on device, and the device quirks we had to work around |
| `docs/NEXT_SESSION.md` | handoff: the on-device gates for the pure pairing/tunnel/install engine |
| `docs/SINGLE_DEVICE.md` | single device, background (Live Activity/notification/Shortcuts) and version freshness: what is possible |
| `variants.json` | the variant registry and runtime resolution rules |
| `bin/barisign` | the single entry point on the signer |
| `sh bin/barisign pair` | the signer → target pairing install |
| `THIRD_PARTY_NOTICES.md` | licences and attribution |

## Licences — please read

BariSign's own code is **MIT**. `third_party/sideinstaller/` is under that project's own
**non-commercial** licence, so **the repository as a whole may not be used commercially**. The forks
planned in `docs/FORK_PLAN.md` are **AGPL-3.0** (SideStore, AltStore and LiveContainer are all AGPL-3.0).
The pure pairing engine was written from the MIT `jkcoxson/idevice` protocol sources and Apple's public
formats; no GPL code is vendored or installed at run time. Details in `THIRD_PARTY_NOTICES.md`.
