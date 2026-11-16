#!/usr/bin/env python3
"""Unit tests for the install-time profile/certificate preflight (Linux only)."""
import datetime
import os
import plistlib
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import signer

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_cert(not_after):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=30))
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)


NOW = datetime.datetime.now(datetime.timezone.utc)
FRESH_CERT = make_cert(NOW + datetime.timedelta(days=300))
OLD_CERT = make_cert(NOW - datetime.timedelta(days=2))


def profile(expires, devices, cert_der):
    return {
        "ExpirationDate": expires,
        "ProvisionedDevices": devices,
        "DeveloperCertificates": [cert_der],
    }


def test_fresh_profile_ok():
    assert signer.install_preflight(
        profile(NOW + datetime.timedelta(days=6), ["a" * 40], FRESH_CERT),
        "a" * 40) == []


def test_expired_profile():
    problems = signer.install_preflight(
        profile(NOW - datetime.timedelta(days=1), ["a" * 40], FRESH_CERT),
        "a" * 40)
    assert any("expired" in problem and "portal" in problem for problem in problems), problems


def test_missing_udid():
    problems = signer.install_preflight(
        profile(NOW + datetime.timedelta(days=6), ["b" * 40], FRESH_CERT),
        "a" * 40)
    assert any("does not include this device" in problem for problem in problems), problems


_MISSING = object()


def _write_app(root, name, bundle_id, groups=_MISSING):
    import plistlib
    path = os.path.join(root, name)
    os.makedirs(path)
    info = {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "x"}
    if groups is not _MISSING:
        info["ALTAppGroups"] = groups
    with open(os.path.join(path, "Info.plist"), "wb") as handle:
        plistlib.dump(info, handle)
    with open(os.path.join(path, "x"), "wb"):
        pass
    return path


def test_group_stamping():
    import plistlib
    import tempfile
    root = tempfile.mkdtemp(prefix="groups-")
    granted = {"entitlements": {"com.apple.security.application-groups":
                               ["group.com.SideStore.SideStore.T1"]}}
    missing = _write_app(root, "A.app", "com.SideStore.SideStore")
    signer.strip_ungranted_app_groups(missing, granted, bundle_id="com.SideStore.SideStore.T1")
    with open(os.path.join(missing, "Info.plist"), "rb") as handle:
        assert plistlib.load(handle)["ALTAppGroups"] == ["group.com.SideStore.SideStore.T1"]
    stale = _write_app(root, "B.app", "com.rileytestut.AltStore", ["group.com.rileytestut.AltStore"])
    signer.strip_ungranted_app_groups(stale, granted, bundle_id="com.rileytestut.AltStore.T1")
    with open(os.path.join(stale, "Info.plist"), "rb") as handle:
        assert plistlib.load(handle)["ALTAppGroups"] == ["group.com.SideStore.SideStore.T1"]
    other = _write_app(root, "C.app", "com.example.Foo", ["group.com.example.Foo"])
    kept = {"entitlements": {"com.apple.security.application-groups": ["group.com.example.Foo"]}}
    signer.strip_ungranted_app_groups(other, kept, bundle_id="com.example.Foo.T1")
    with open(os.path.join(other, "Info.plist"), "rb") as handle:
        assert plistlib.load(handle)["ALTAppGroups"] == ["group.com.example.Foo"]
    dropped = _write_app(root, "D.app", "com.example.Bar", ["group.com.example.Bar"])
    signer.strip_ungranted_app_groups(dropped, granted, bundle_id="com.example.Bar.T1")
    with open(os.path.join(dropped, "Info.plist"), "rb") as handle:
        assert "ALTAppGroups" not in plistlib.load(handle)
    nogroup = _write_app(root, "E.app", "com.rileytestut.AltStore", ["group.com.rileytestut.AltStore"])
    signer.strip_ungranted_app_groups(nogroup, {"entitlements": {}}, bundle_id="com.rileytestut.AltStore.T1")
    with open(os.path.join(nogroup, "Info.plist"), "rb") as handle:
        assert "ALTAppGroups" not in plistlib.load(handle)


def test_expired_cert():
    problems = signer.install_preflight(
        profile(NOW + datetime.timedelta(days=6), ["a" * 40], OLD_CERT),
        "a" * 40)
    assert any("certificate expired" in problem for problem in problems), problems


def test_blob_parse():
    inner = plistlib.dumps({"ExpirationDate": NOW}, fmt=plistlib.FMT_XML)
    fake_cms = b"\x30\x82\x99\x99garbage" + inner + b"\x00trailer"
    parsed = signer.parse_mobileprovision_blob(fake_cms)
    assert "ExpirationDate" in parsed
    bare = plistlib.dumps({"a": 1}, fmt=plistlib.FMT_XML)
    assert signer.parse_mobileprovision_blob(bare) == {"a": 1}


if __name__ == "__main__":
    for name, function in sorted([(k, v) for k, v in globals().items()
                                  if k.startswith("test_") and callable(v)]):
        function()
        print("ok  %s" % name)
