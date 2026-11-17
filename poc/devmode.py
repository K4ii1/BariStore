#!/usr/bin/env python3
# =============================================================================
#  BariSign — Developer Mode over the tunnel (MIT)
#
#  Reads whether Developer Mode is on and asks iOS to show the switch or turn
#  it on, through the same pairing + tunnel as the install. No root, no
#  exploit, no extra entitlement: lockdownd answers GetValue over the tunnel,
#  and AMFI's RSD shim takes an {action} request and closes the connection.
#
#  Protocol facts (MIT sources, no copied code):
#    * idevice (jkcoxson, MIT): lockdown GetValue {Label, Request, Key?, Domain?}
#      answers {"Value": ...}; AMFI service com.apple.amfi.lockdown(.shim.remote)
#      takes {"action": N} and answers {"success": ...} or {"Error": ...}.
#    * siboot (FrizzleM, MIT): status key DeveloperModeStatus in domain
#      com.apple.security.mac.amfi; action 0 shows the switch (no restart),
#      action 1 turns it on (the iPhone restarts; refused with a passcode set,
#      in which case show the switch instead). iOS closes AMFI after one
#      request, so each action gets a fresh connection.
#
#  Like siboot's developer-mode: only useful while the iPhone still answers on
#  its pairing port with this pairing. UNTESTED ON A DEVICE.
# =============================================================================

import device_services
import remote_xpc

AMFI_DOMAIN = "com.apple.security.mac.amfi"
STATUS_KEY = "DeveloperModeStatus"

LOCKDOWN_NAMES = (
    "com.apple.mobile.lockdown.remote.trusted",
    "com.apple.mobile.lockdown",
)
AMFI_NAMES = (
    "com.apple.amfi.lockdown.shim.remote",
    "com.apple.amfi.lockdown",
)

SHOW, TURN_ON = 0, 1


class DevmodeError(Exception):
    """What the user can act on: unreachable service, refusal, restart."""


def _port(services, names):
    """First matching RSD service port, or raise naming what is offered."""
    for name in names:
        entry = services.get(name)
        if isinstance(entry, dict):
            port = entry.get("Port")
            if isinstance(port, str):
                try:
                    port = int(port)
                except ValueError:
                    continue
            if isinstance(port, int) and 0 < port < 65536:
                return port
    offered = ", ".join(sorted(str(key) for key in services)) or "(none)"
    raise DevmodeError("the device offers no %s (offers: %s)"
                       % (names[0], offered))


async def status(stack, server_address, services):
    """True/False/None: Developer Mode on, off, or unreadable."""
    port = _port(services, LOCKDOWN_NAMES)
    service = await device_services.open_service(stack, server_address, port)
    try:
        response = await service.send_receive({
            "Label": "BariSign",
            "Request": "GetValue",
            "Key": STATUS_KEY,
            "Domain": AMFI_DOMAIN,
        })
    finally:
        await service.close()
    if "Error" in response:
        return None
    value = response.get("Value")
    return bool(value) if isinstance(value, bool) else None


async def _action(stack, server_address, services, action):
    """Send one AMFI action on a fresh connection; return (ok, hung_up, text)."""
    port = _port(services, AMFI_NAMES)
    service = await device_services.open_service(stack, server_address, port)
    try:
        response = await service.send_receive({"action": action})
    except Exception as exc:                                    # noqa: BLE001
        return False, True, "hung up: %s" % exc
    finally:
        await service.close()
    if response.get("success"):
        return True, False, ""
    error = response.get("Error") or response.get("error") or "refused"
    return False, False, str(error)


async def show_switch(stack, server_address, services):
    """Ask iOS to reveal the Developer Mode switch. No restart."""
    ok, hung_up, text = await _action(stack, server_address, services, SHOW)
    if ok:
        return
    if hung_up:
        raise DevmodeError("the iPhone stopped answering; check Settings > "
                           "Privacy & Security for Developer Mode")
    raise DevmodeError("the iPhone refused to show Developer Mode: %s" % text)


async def turn_on(stack, server_address, services):
    """Ask iOS to turn Developer Mode on now. The iPhone restarts.

    With a passcode set iOS refuses ("Device has a passcode set"); without one
    it restarts before answering, which looks like a hang-up.
    """
    ok, hung_up, text = await _action(stack, server_address, services, TURN_ON)
    if ok or hung_up:
        return
    if "passcode" in text.lower():
        raise DevmodeError("passcode-set")
    raise DevmodeError("the iPhone refused to turn Developer Mode on: %s" % text)
