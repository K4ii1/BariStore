# BariSign

Install **SideStore** — or **LiveContainer + SideStore**, or **AltStore Classic** — on an iPhone or iPad
**with no computer**, using your own free Apple ID. The design needs **two iOS/iPadOS devices on the
same Wi-Fi**: a signer (a-Shell) and a target (Safari + Settings).

> **New engine, device test pending:** `sh bin/barisign pair` now runs entirely in a-Shell. The
> RPPairing host, TLS 1.2 PSK tunnel, userspace TCP, RSD, AFC and `installation_proxy` are pure Python
> on the `cryptography` 3.4.8 that a-Shell ships — no qh3, no sslpsk, no pip, no native wheel, no
> second app. The whole chain is tested on Linux; the **on-device run is the remaining gate**.
> See `docs/NEXT_SESSION.md`.

| Role | What it is | What it runs |
|---|---|---|
| **Signer** | the device that signs and installs | **a-Shell** + BariSign |
| **Target** | the device that gets the app | Safari + Settings only |

Both devices may be an **iPhone or an iPad**; iOS and iPadOS both work. The role is chosen at run time.
They must be on the **same Wi-Fi**. The target never installs a-Shell or BariSign.

> **Status:** the signer path is verified on a real device running iOS 27: Apple sign-in, the
> developer portal, signing, and launching the signed app. The **pure pairing/tunnel/install engine**
> is written and passes its Linux protocol tests; the **pair-first UDID** and the
> **signer → target pairing install** still need the user's device run. The fallback **UDID page** is
> written too.

---

## How the flow works

1. On the **signer**, install a-Shell and BariSign, then run `sh bin/barisign`.
2. The signer downloads the chosen variant's **original** IPA and offers to share it to the target.
   If the target has never had Developer Mode, install that IPA once; the Developer Mode switch
   appears after the failed launch attempt. (This is only a trigger; it is not the app we sign.)
3. Pair the target: on the **target** open **Settings → Privacy & Security → Developer Mode →
   Paired Macs**, pick **BariSign**, enter the code. The signer takes the target's **UDID from the
   pairing** and continues; the median page is not needed.
4. Signer: Apple sign-in, developer portal (device + App ID + certificate + profile), sign.
5. Install with the same pairing record: `sh bin/barisign pair`. The signer advertises again, the target
   enters the code, and the signer installs over Wi-Fi with `installation_proxy`. The pairing file is
   saved under `state/` and written into AltStore (`Documents/ALTPairingFile.plist`) or SideStore
   (`Documents/ALTPairingFile.mobiledevicepairing`) so the installed app can refresh itself.
6. On the target, trust the developer and open the app.

> **How the install works:** the same pairing record opens the target's `_remotepairing` service over
> Wi-Fi. A pure TLS 1.2 PSK tunnel carries a small userspace TCP stack; `installation_proxy` installs
> the staged IPA as a developer package, and house_arrest writes the pairing file into the app. The
> target only trusts the developer and opens the app. **Untested on a device until the user runs it.**

If pairing cannot produce a UDID (old target, Developer Mode not available), the signer falls back to
a short-lived page on its Wi-Fi address: the target opens `http://<signer-ip>:<port>/`, installs the
**median.co/udid** profile, copies the UDID and submits it.

---

## What works

| | |
|---|---|
| **Apple sign-in** (free ID, 2FA) | ✅ verified |
| **Device, certificate, profile** (developer portal) | ✅ verified |
| **Download + sign + verify** | ✅ verified — the signed IPA installs and the app launches on a device |
| **UDID from pairing** (pair-first) | ⚠️ pure engine written, Linux-tested; device run pending |
| **UDID page** fallback served by the signer | ⚠️ written, untested on a device |
| **Signer → target pairing install** (`sh bin/barisign pair`) | ⚠️ pure engine written, Linux-tested; device run pending |
| **Two devices, no computer** | the design; the pure engine removes the last native dependency |

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
sh bin/barisign          # guided: check -> variant -> download -> pair/UDID -> Apple -> portal -> sign -> install
sh bin/barisign pair     # pair the target and install over Wi-Fi
sh bin/barisign status   # what is already known
sh bin/barisign --help   # every command
```

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
the signer reads the target's UDID from the pairing/tunnel. No median profile is needed in the normal
flow.

If pairing cannot provide it, `sh bin/barisign udid` serves a fallback page on the signer's Wi-Fi
address: the target opens it in Safari, installs the `median.co/udid` profile, copies the UDID and
submits it. `sh bin/barisign udid --manual` keeps a paste-on-the-signer fallback for testing.
`docs/UDID_OPTIONS.md` lists other UDID sites (not affiliated with us) and self-hosting.

---

## Which variant you get

| # | Variant | Source |
|---|---|---|
| 1 | **SideStore** (stable) | `SideStore/SideStore` |
| 2 | **SideStore** (nightly — *may be unstable*) | `SideStore/SideStore`, tag `nightly` |
| 3 | **LiveContainer + SideStore** (stable) | `LiveContainer/LiveContainer` |
| 4 | **LiveContainer + SideStore** (nightly) | `LiveContainer/LiveContainer`, tag `nightly` |
| 5 | **AltStore Classic** (stable) | `altstoreio/AltStore` |

Every version is resolved **at runtime** from the project's official release page — never pinned here —
and you are shown which version you are about to get. `variants.json` is the machine-readable list.

---

## Your Apple ID and your data

- **Your password is never transmitted.** Apple's sign-in is SRP-6a: the password becomes a one-time proof
  on the signer. It is never written to disk.
- **The anisette server never sees your account.** It is asked only for device-identity headers, with a
  random identifier we generate — never your Apple ID, password or token.
- **No BariSign server exists.** The UDID page is served only from the signer on your own Wi-Fi for the
  duration of that step. Nothing is collected: no analytics, no telemetry, no accounts.
- TLS verification is never disabled anywhere in this project.

---

## Documentation

| File | What it is |
|---|---|
| **`GUIDE.md`** | step-by-step, in plain language |
| `docs/PAIRING_INSTALL.md` | how the signer pairs with and installs on the target |
| `docs/UDID_OPTIONS.md` | UDID sources, including the signer page |
| `docs/ANISETTE.md` | anisette servers: what they see, which ones we use, how to pin or self-host |
| `docs/PLAN_V2.md` | the current architecture and why |
| `docs/FORK_PLAN.md` | the pairing module inside the forked apps: licences, CI, risks |
| `docs/RESULTS.md` | what is verified on device, and the device quirks we had to work around |
| `docs/NEXT_SESSION.md` | handoff for the remaining pure a-Shell tunnel work |
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
