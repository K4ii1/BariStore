# Third-Party Notices

BariStore is 100% **MIT Licensed** (`LICENSE`). All protocol layers (RPPairing, TLS 1.2 PSK, userspace IPv6/TCP, RemoteXPC/RSD, AFC, `house_arrest`, `installation_proxy`, `lockdownd`/`amfi`, `debug_proxy`, Mach-O/CMS code signing, Anisette v1/v3, Apple GrandSlam SRP-6a, and Developer Portal client) are clean-room MIT implementations built on Python's standard library and a-Shell's built-in `cryptography` package.

## Public Trust Anchors & Certificates

### Mozilla CA Bundle — `third_party/ca-bundle/cacert.pem`
- Source: `https://curl.se/ca/cacert.pem` (Mozilla CA certificate store distributed by the curl project)
- License: MPL 2.0 / Public Domain
- Purpose: Provides TLS root certificates because a-Shell's Python environment ships with an empty default OpenSSL trust store.

### Apple Root CA — `third_party/apple-roots/`
- Source: `https://www.apple.com/appleca/AppleIncRootCertificate.cer`
- SHA-256: `B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24`
- Purpose: Public Apple trust anchor used exclusively for verifying `*.apple.com` TLS connections.

## Protocol References (No Code Copied)

| Project | License | Role |
|---|---|---|
| `jkcoxson/idevice` | MIT | Protocol reference for RPPairing, TLS-PSK, CDTunnel, RSD, AFC, `installation_proxy`, `amfi`, and `debug_proxy` |
| `nab138/isideload` | MIT | Protocol reference for Apple GSA SRP-6a, Anisette v3, Developer Portal, and App Groups |
| `zhlynn/zsign` | MIT | Format reference for Apple Mach-O CodeDirectory and CMS attributes |
| `FrizzleM/siboot` | MIT | Protocol reference for AMFI Developer Mode actions (`0` / `1`) |
