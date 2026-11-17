# Reading your UDID — pairing only (0.9.18)

BariSign needs **this iPhone's UDID** because a free Apple ID can only sign apps for devices that are
registered on it. There is nothing secret about a UDID: it is a hardware identifier developers paste into
portals every day. It is **not** a credential, and no Apple ID or password is involved in getting it.

The **only** route is pairing: the run pairs this iPhone with itself and
reads the UDID from the pairing, then saves it.

> There is no UDID page and no paste box in BariSign (removed 0.9.18): pairing is
> the only route. If pairing itself stays unreachable, that is a bug — send the exact
> screen text plus `state/pair_debug.log` instead of hunting for a workaround.

iOS only hands the UDID over through a **Profile Service** profile from **HTTPS with a certificate
it trusts**. If you ever need a UDID without BariSign's pairing, these independent options still
exist (not affiliated with us, not vetted, they see the UDID you send them — never type an Apple
ID or password into one; use Safari; remove the profile afterwards):

- **median.co/udid** — one tap, no trust switch.
- **udid.tech** (at the time of writing `udid.io` and `get.udid.io` both redirect there;
  checked 2026-10-29) — same idea.
- **Serve the profile yourself** (no third party): bring your own HTTPS endpoint with a certificate
  iOS trusts (a CA you generate and install once is enough). The profile is a `.mobileconfig`
  containing a `Profile Service` payload whose `URL` names your server:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Profile Service</string>
  <key>PayloadIdentifier</key><string>example.udid</string>
  <key>PayloadUUID</key><string>6E1B2E45-1A0E-4E3E-9E4B-4E3B7F0A1C22</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadDisplayName</key><string>Get UDID</string>
  <key>PayloadOrganization</key><string>example</string>
  <key>PayloadContent</key><dict>
    <key>URL</key><string>https://your-server.example/udid</string>
    <key>DeviceAttributes</key><array>
      <string>UDID</string><string>PRODUCT</string><string>VERSION</string><string>SERIAL</string>
    </array>
  </dict>
</dict></plist>
```

Rules that matter, learned the hard way:

- The chain must be **trusted** by the device. A self-signed root works **only** after you install it and
  switch its trust ON in **Certificate Trust Settings**.
- Serve the profile from the **same host** the profile's `URL` names, and keep the server running: iOS
  posts the moment the profile finishes installing.
- **Safari only.** Other browsers save the file instead of handing it to Settings.
- iOS says the installed profile is **empty** — expected: a `Profile Service` payload configures nothing,
  and the UDID has already been posted by then.

---

## What a valid UDID looks like

- **40 hex characters** on older devices, e.g. `a1b2c3d4e5f60718293a4b5c6d7e8f9012345678`
- **8 + 16 hex characters** on A12-and-later devices, written `00008110-001a2c3e0e91801e` (the dash is
  optional).

BariSign lowercases it, restores the dash when needed, and refuses anything else.
