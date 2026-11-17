#!/usr/bin/env python3
"""Unit tests for profile preflight, App Group stamping, IPA inspection, and Apple crypto."""
import datetime
import os
import plistlib
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

from baristore import apple, signer


def make_cert(not_after):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


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
    assert (
        signer.install_preflight(
            profile(NOW + datetime.timedelta(days=6), ["a" * 40], FRESH_CERT), "a" * 40
        )
        == []
    )


def test_expired_profile():
    problems = signer.install_preflight(
        profile(NOW - datetime.timedelta(days=1), ["a" * 40], FRESH_CERT), "a" * 40
    )
    assert any("expired" in p for p in problems), problems


def test_missing_udid():
    problems = signer.install_preflight(
        profile(NOW + datetime.timedelta(days=6), ["b" * 40], FRESH_CERT), "a" * 40
    )
    assert any("does not include this device" in p for p in problems), problems


def test_expired_cert():
    problems = signer.install_preflight(
        profile(NOW + datetime.timedelta(days=6), ["a" * 40], OLD_CERT), "a" * 40
    )
    assert any("certificate expired" in p for p in problems), problems


def test_ipa_inspect_with_extensions():
    with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as tf:
        path = tf.name
    try:
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr(
                "Payload/Main.app/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.example.Main",
                        "CFBundleDisplayName": "Main App",
                        "CFBundleShortVersionString": "2.4.0",
                    },
                    fmt=plistlib.FMT_XML,
                ),
            )
            zf.writestr(
                "Payload/Main.app/PlugIns/Widget.appex/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": "com.example.Main.Widget",
                        "CFBundleDisplayName": "Main Widget",
                    },
                    fmt=plistlib.FMT_XML,
                ),
            )
        info = signer.inspect_ipa(path)
        assert info["name"] == "Main App"
        assert info["bundle_id"] == "com.example.Main"
        assert info["version"] == "2.4.0"
        assert info["has_extensions"] is True
        assert len(info["extensions"]) == 1
        assert info["extensions"][0]["folder"] == "Widget.appex"
        assert info["extensions"][0]["bundle_id"] == "com.example.Main.Widget"
    finally:
        os.unlink(path)


def test_clean_room_apple_crypto():
    # AES-CBC with PKCS#7 padding
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plain = b"baristore-selftest"
    pad = 16 - (len(plain) % 16)
    padded = plain + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    assert apple.aes_cbc_decrypt(key, iv, ct) == plain

    # AES-256-GCM with 16-byte GrandSlam nonce
    gcm_key = os.urandom(32)
    nonce16 = os.urandom(16)
    aad = b"XYZ"
    genc = Cipher(algorithms.AES(gcm_key), modes.GCM(nonce16)).encryptor()
    genc.authenticate_additional_data(aad)
    gct = genc.update(b"<dict><key>status-code</key><integer>200</integer></dict>") + genc.finalize()
    dec = apple.aes_gcm_decrypt(gcm_key, nonce16, gct, aad, genc.tag)
    parsed = apple.loads_bare_plist(dec)
    assert parsed["status-code"] == 200


if __name__ == "__main__":
    for name, function in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_") and callable(v)]
    ):
        function()
        print("ok  %s" % name)
