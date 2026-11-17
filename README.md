# BariSign

<img src="barisign.svg" width="128" alt="BariSign icon">

Install **SideStore** — or **LiveContainer + SideStore**, or **AltStore Classic** — on your iPhone or iPad
**with no computer**, using your own free Apple ID. Everything runs **on the one device**: a-Shell +
BariSign, LocalDevVPN, and this iPhone itself.

> **Status (0.9.23):** Apple sign-in, the developer portal, pairing over loopback (M1–M6), signing and
> the tunnel/install engine run from Linux tests plus on-device runs. New in this revision: a web page
> UI in a-Shell's internal browser (no terminal typing), Developer Mode via the tunnel (no second
> device, no trigger install), and single-device-first docs. The loopback install and the sheet UI
> are **UNVERIFIED ON A DEVICE** — run it and report back.

---

## How the flow works

```
barisign
```

opens a page over the terminal. Tap **Start** and it runs the whole install on this iPhone:

1. **Requirements** — LocalDevVPN connected (probed live; it waits for you).
2. **Apple ID** — sign-in with anisette (saved session reused: no password or 2FA until Apple refuses it).
3. **Portal** — picks your developer team for this Apple ID.
4. **Pairing** — this iPhone pairs with itself (Settings → Developer → Paired Macs → BariSign, enter the
   printed PIN). The page plays silence so iOS holds the app while you are in Settings.
5. **Variant** — SideStore / LiveContainer+SideStore / AltStore Classic, stable or nightly, or your own IPA.
6. **Download** — resolved live from the project's releases, size + SHA-256 checked.
7. **Developer Mode** — read over the tunnel; if off or hidden, the switch is shown (no restart).
   Turning it on restarts the iPhone and ends the run with a restart card: flip it, restart, run
   again — everything is saved and the run jumps straight back. No trigger install, no second device.
8. **Sign & Install** — registers this iPhone, signs the IPA, installs it over the same loopback
   tunnel; trust the developer, open the app. **Stop** ends the run anywhere (even mid-wait);
   **Back** re-asks the previous step and replays your answers; the **Settings** card holds the
   version, what is saved, an update check, a pairing-file export and a forget button.

No computer, no second device, no AirDrop, no OTA, no enterprise certificate.

---

## Get it

In a-Shell on the **iPhone itself**:

```
curl -fsSL https://raw.githubusercontent.com/barismd/barisign/main/install.sh | sh
```

One line, run from anywhere in a-Shell. It lays down `barisign` (the launcher, so no
`cd` is ever needed) plus `barisign_files/` with everything else; an old `barisign/`
folder is moved into place with its state kept.

`barisign update` self-updates everything in place. Your saved state in
`barisign_files/state/` is kept.
There is **no pip step**: the engine is part of the program files.

```
barisign          # web UI: the whole install on this iPhone
barisign shell    # terminal run without the web page
barisign status   # what is saved
barisign --help   # every command
```

---

## Requirements

| | |
|---|---|
| Device | iPhone/iPad, **iOS/iPadOS 27 or newer** |
| Apple account | a **free** Apple ID — no paid Developer Program membership |
| Apps | **a-Shell** (free, App Store) + **LocalDevVPN** (free, App Store; connected during pairing/install) |
| Computer | **none** |
| Network | internet for Apple and the IPA download; pairing/install stay on-device |

On the target: LocalDevVPN for SideStore to refresh apps after install.

---

## The UDID, in one paragraph

A free Apple ID signs apps for **specific devices**, so the **UDID** must be known. Pairing gives it:
BariSign advertises as a pairable host, you pair from Settings, and the UDID comes back through the
tunnel. There is no UDID page (removed in 0.9.18); `docs/UDID_OPTIONS.md` lists independent UDID
sources (not affiliated with us).

---

## Which variant you get

| # | Variant | Source |
|---|---|---|
| 1 | **SideStore** (stable) | `SideStore/SideStore` |
| 2 | **SideStore** (nightly — *may be unstable*) | `SideStore/SideStore`, tag `nightly` |
| 3 | **LiveContainer + SideStore** (stable) | `LiveContainer/LiveContainer` |
| 4 | **LiveContainer + SideStore** (nightly) | `LiveContainer/LiveContainer`, tag `nightly` |
| 5 | **AltStore Classic** (stable) | `altstoreio/AltStore` |
| 6 | **Custom IPA** (your own file, already on the device) | your file; pick `custom IPA` in the variant step |

Every version is resolved **at runtime** from the project's official release page — never pinned here —
and you are shown which version you are about to get (stable: the tag; nightly: the asset date,
because its `published_at` is stale). A cached IPA is reused only when size **and** GitHub's SHA-256
match; offline runs say `(no GitHub; using the saved file)`. `variants.json` is the machine-readable list.

---

## Your Apple ID and your data

- **Your password is never transmitted.** Apple's sign-in is SRP-6a: the password becomes a one-time proof
  on the device. It is never written to disk.
- **The anisette server never sees your account.** It is asked only for device-identity headers, with a
  random identifier we generate — never your Apple ID, password or token.
- The saved portal *session token* (not the password) is reused so 2FA is not asked again; it lives in
  sandboxed `state/`, is never printed, and `forget`/`reset` wipe it.
- **The web page never leaves the device.** It is served on 127.0.0.1 with a per-run random path, like
  siboot's page; closing the sheet ends nothing by itself, Stop (or the end of the run) stops the server.
- **No BariSign server exists.** Nothing is collected: no analytics, no telemetry, no accounts.
- TLS verification is never disabled anywhere in this project.

---

## Documentation

| File | What it is |
|---|---|
| **`GUIDE.md`** | step-by-step, in plain language |
| `docs/PLAN_V2.md` | the current architecture and why |
| `docs/PAIRING_INSTALL.md` | pairing + Developer Mode + `installation_proxy` over loopback |
| `docs/DEVELOPER_MODE.md` | Developer Mode via the tunnel (no trigger install) |
| `docs/UDID_OPTIONS.md` | UDID sources (pairing only; page removed in 0.9.18) |
| `docs/ANISETTE.md` | anisette servers: what they see, which ones we use, how to pin or self-host |
| `docs/RESULTS.md` | what is verified on device, and the device quirks we had to work around |
| `docs/NEXT_SESSION.md` | handoff: the on-device gates |
| `variants.json` | the variant registry and runtime resolution rules |
| `barisign` | the single entry point (web UI) |
| `THIRD_PARTY_NOTICES.md` | licences and attribution |

## Licences — please read

BariSign's own code is **MIT**. `third_party/sideinstaller/` is under that project's own
**non-commercial** licence, so **the repository as a whole may not be used commercially**. The pure
pairing/tunnel/install engine and the Developer Mode + web UI code are original MIT implementations
written from the MIT `jkcoxson/idevice` protocol sources and Apple's public formats; no GPL code is
vendored or installed at run time. Details in `THIRD_PARTY_NOTICES.md`.
