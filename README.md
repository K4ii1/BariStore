# BariStore

<img src="baristore.svg" width="112" alt="BariStore icon">

**BariStore** is a complete, 100% on-device iOS/iPadOS App Store, IPA signer, and StikDebug-style JIT Enabler that runs inside **a-Shell** with **no computer** and **no second device**.

Using your own free Apple ID and **LocalDevVPN**, BariStore pairs with your iPhone, enables Developer Mode over the loopback tunnel, signs and installs apps from **AltSources** or custom `.ipa` files, refreshes 7-day app signatures, and enables **JIT** on sideloaded apps.

---

## Quick Start (On Your iPhone / iPad)

Open **a-Shell** and run:

```sh
curl -fsSL https://raw.githubusercontent.com/barismd/BariStore/main/install.sh | sh
```

Then start BariStore at any time with a single command:

```sh
baristore
```

To update BariStore in place while preserving your Apple ID session, pairing file, and installed apps:

```sh
baristore update
```

---

## How It Works

### First-Time Onboarding
When you run `baristore` for the first time, it opens a clean setup wizard inside a-Shell's internal browser:

1. **LocalDevVPN Check** — Verifies that LocalDevVPN is connected on `10.7.0.1`.
2. **Instant Device Pairing** — Pre-computes a 6-digit PIN and 3072-bit SRP-6a verifier *before* advertising over 250ms mDNS broadcast, holds a-Shell awake in the background with a non-zero sub-audible audio loop + optional floating Picture-in-Picture (PiP) PIN window, and pairs from **Settings → Developer → Paired Macs → BariStore** (or imports an existing pairing file).
3. **Developer Mode Over Tunnel** — Checks Developer Mode status over the loopback tunnel. If disabled or hidden, reveals the toggle in **Settings → Privacy & Security → Developer Mode** or enables it immediately.
4. **Apple ID Sign-In** — Authenticates via Anisette + SRP-6a + 2FA and saves your developer session so you **never get logged out**.

### The Store Interface (Every Subsequent Launch)
Once setup is complete, `baristore` opens **directly into the Store screen** every time—even offline or when LocalDevVPN is disconnected. Connection checks only happen when you tap **Install**, **Refresh**, **Delete**, or **Enable JIT**.

- **Featured Tab**:
  - **AltSources Support**: Ships with trusted, open-source community AltSources pre-installed (AltStore Official, SideStore Official & Community Picks, StikDebug, Provenance, UTM, OatmealDome/DolphiniOS, Flycast, PojavLauncher, Yattee) and lets you add or remove any source URL.
  - **Multi-Source Detection**: When an app is offered by more than one AltSource, BariStore detects it and lets you choose which source to install from.
  - **Stores & Containers Showcase**: Built-in one-tap installation for **SideStore** (Stable & Nightly), **LiveContainer + SideStore** (Stable & Nightly), standalone **LiveContainer** (Stable & Nightly), and **AltStore Classic**—automatically generating and injecting the required pairing files (`ALTPairingFile.mobiledevicepairing`, `PairingFile_RemoteRP.plist`, `ALTPairingFile.plist`, and preferences) into each app's container.
  - **Custom IPA & App ID Slot Saver**: Pick any `.ipa` file directly from the WebView file picker, customize its Display Name or Bundle ID, or strip app extensions (`.appex`) to save your free Apple account's 10 App ID slots.
- **My Apps Tab**:
  - Tracks your installed apps with a 7-day expiration countdown.
  - **Refresh & Refresh All**: Re-signs and installs apps over loopback before they expire.
  - **⚡ Enable JIT (StikDebug-style)**: Attaches and detaches `debugserver` over `com.apple.internal.dt.remote.debugproxy` on the RSD tunnel to enable JIT (`CS_DEBUGGED`) on running apps.
  - **🔑 Inject Pairing**: Writes the normalized RPPairing file directly into supported apps via `house_arrest`.
  - **Delete**: Uninstalls apps directly from your device via `installation_proxy`.
- **Options Tab**:
  - View your signed-in Apple ID, developer team, registered App IDs (and remaining slots out of 10), and development certificates.
  - Export or import your pairing file (`ALTPairingFile.mobiledevicepairing`), re-pair your device, switch themes (**System / Light / Dark**), test Anisette servers, clear cache, or reset BariStore.

---

## Security & Privacy

- **Your password never leaves your device.** Apple sign-in uses SRP-6a: your password becomes a local cryptographic proof and is never written to disk or sent over the network.
- **Anisette servers never see your Apple ID, password, or tokens.** They only provide anonymous machine-identity headers.
- **Loopback Web UI security.** The UI runs on `127.0.0.1` on a random port behind a per-run 128-bit token with strict `Host` validation.
- **No telemetry, no external BariStore server, and TLS verification is always enforced.**

---

## License

BariStore is 100% **MIT Licensed**. See `LICENSE` and `THIRD_PARTY_NOTICES.md` for details.
