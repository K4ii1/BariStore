#!/usr/bin/env python3
"""Unit tests for the custom-IPA picker (Linux only)."""
import os
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import barisign


def _make_ipa(path, bundle_id="com.example.Widget"):
    import plistlib
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "Payload/Widget.app/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": bundle_id}, fmt=plistlib.FMT_XML))
        archive.writestr("Payload/Widget.app/big.bin", b"\0" * (2 * 1024 * 1024))


def test_picker_lists_custom_dir_newest_first():
    tmp = tempfile.mkdtemp(prefix="customs-")
    custom = os.path.join(tmp, "Custom IPAs")
    os.makedirs(custom)
    old = os.path.join(custom, "old.ipa")
    new = os.path.join(custom, "new.ipa")
    _make_ipa(old)
    _make_ipa(new)
    os.utime(old, (1000000000, 1000000000))
    open(os.path.join(custom, "tiny.ipa"), "wb").write(b"x")
    open(os.path.join(custom, "note.txt"), "wb").write(b"x")
    real = barisign.CUSTOM_IPA_DIR
    barisign.CUSTOM_IPA_DIR = custom
    try:
        found = barisign._find_signer_ipas()
        assert found == [new, old], found
        assert barisign._resolve_ipa_path(new) == new
        assert barisign._resolve_ipa_path("new.ipa") == new
        assert barisign._resolve_ipa_path(os.path.join(custom, "missing.ipa")) == ""
        assert barisign._ipa_bundle_id(new) == "com.example.Widget"
        assert barisign._ipa_bundle_id(os.path.join(custom, "note.txt")) == ""
    finally:
        barisign.CUSTOM_IPA_DIR = real


if __name__ == "__main__":
    test_picker_lists_custom_dir_newest_first()
    print("ok  test_picker")
