"""
test_permissions.py — Unit tests for Member 1's permissions module
Run from the backend/ directory: pytest tests/test_permissions.py -v
"""

import io
import os
import sys
import zipfile
import tempfile
import pytest

# Ensure the backend package root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.permissions import (
    classify_permission,
    parse_permissions_from_apk,
    analyze_permissions,
    _to_risk,
    _to_label,
    _justification_score,
    PERMISSIONS_DB,
)


# ── Helpers ───────────────────────────────────────────────────────────────

def _make_apk(permissions: list, extra_files: dict = None) -> str:
    """
    Build a minimal but valid APK (ZIP) whose binary AndroidManifest.xml
    contains the given permission strings in UTF-16 LE encoding — exactly
    the format produced by the Android build toolchain.

    Returns the path to a temporary .apk file.
    """
    # Build a fake binary manifest that encodes permission strings
    # as UTF-16 LE so the parser's regex can find them.
    manifest_content = "\x00".join(permissions)   # raw string representation
    manifest_bytes = manifest_content.encode("utf-16-le")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        if extra_files:
            for name, content in extra_files.items():
                zf.writestr(name, content)
    buf.seek(0)

    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    tmp.write(buf.read())
    tmp.close()
    return tmp.name


# ══════════════════════════════════════════════════════════════════════════
# TEST 1 — classify_permission: known permission
# ══════════════════════════════════════════════════════════════════════════
def test_classify_known_permission():
    result = classify_permission("android.permission.CAMERA")
    assert result["permission"] == "android.permission.CAMERA"
    assert result["protection_level"] == "dangerous"
    assert result["privacy_impact"] == "High"
    assert result["category"] == "Hardware Access"
    assert "description" in result
    assert "recommendation" in result


# ══════════════════════════════════════════════════════════════════════════
# TEST 2 — classify_permission: unknown permission gets safe defaults
# ══════════════════════════════════════════════════════════════════════════
def test_classify_unknown_permission():
    result = classify_permission("com.custom.permission.UNKNOWN_THING")
    assert result["protection_level"] == "unknown"
    assert result["privacy_impact"] == "Unknown"
    assert result["category"] == "Unknown"
    assert result["recommendation"] == "Review permission manually"


# ══════════════════════════════════════════════════════════════════════════
# TEST 3 — _to_risk: correct mapping from classification
# ══════════════════════════════════════════════════════════════════════════
def test_risk_mapping():
    assert _to_risk({"protection_level": "normal",    "privacy_impact": "Low"})    == "low"
    assert _to_risk({"protection_level": "dangerous",  "privacy_impact": "Medium"}) == "med"
    assert _to_risk({"protection_level": "dangerous",  "privacy_impact": "High"})   == "high"
    assert _to_risk({"protection_level": "special",    "privacy_impact": "Low"})    == "high"
    assert _to_risk({"protection_level": "unknown",    "privacy_impact": "Unknown"}) == "low"


# ══════════════════════════════════════════════════════════════════════════
# TEST 4 — _to_label: correct Necessary / Optional / Excessive assignment
# ══════════════════════════════════════════════════════════════════════════
def test_label_mapping():
    necessary_cases = [
        {"protection_level": "normal",   "privacy_impact": "Low"},      # INTERNET
        {"protection_level": "normal",   "privacy_impact": "Medium"},   # NFC
        {"protection_level": "dangerous","privacy_impact": "Low"},      # POST_NOTIFICATIONS
    ]
    for case in necessary_cases:
        assert _to_label(case) == "Necessary", f"Expected Necessary for {case}"

    optional_cases = [
        {"protection_level": "dangerous", "privacy_impact": "Medium"},  # BLUETOOTH_SCAN
        {"protection_level": "unknown",   "privacy_impact": "Unknown"},
    ]
    for case in optional_cases:
        assert _to_label(case) == "Optional", f"Expected Optional for {case}"

    excessive_cases = [
        {"protection_level": "special",   "privacy_impact": "High"},   # MANAGE_EXTERNAL_STORAGE
        {"protection_level": "special",   "privacy_impact": "Low"},    # any special
        {"protection_level": "dangerous", "privacy_impact": "High"},   # CAMERA
    ]
    for case in excessive_cases:
        assert _to_label(case) == "Excessive", f"Expected Excessive for {case}"


# ══════════════════════════════════════════════════════════════════════════
# TEST 5 — parse_permissions_from_apk: extracts permissions from a real
#           APK-like ZIP with UTF-16 LE encoded manifest
# ══════════════════════════════════════════════════════════════════════════
def test_parse_permissions_from_apk():
    expected = [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
        "android.permission.RECORD_AUDIO",
    ]
    apk_path = _make_apk(expected)
    try:
        found = parse_permissions_from_apk(apk_path)
        for perm in expected:
            assert perm in found, f"{perm} not found in parsed permissions"
    finally:
        os.unlink(apk_path)


# ══════════════════════════════════════════════════════════════════════════
# TEST 6 — parse_permissions_from_apk: handles missing manifest gracefully
# ══════════════════════════════════════════════════════════════════════════
def test_parse_permissions_missing_manifest():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("res/layout/main.xml", "<LinearLayout/>")
    buf.seek(0)
    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    tmp.write(buf.read())
    tmp.close()
    try:
        result = parse_permissions_from_apk(tmp.name)
        assert result == []   # no manifest → empty list, no crash
    finally:
        os.unlink(tmp.name)


# ══════════════════════════════════════════════════════════════════════════
# TEST 7 — analyze_permissions: full pipeline returns correct structure
# ══════════════════════════════════════════════════════════════════════════
def test_analyze_permissions_structure():
    perms = [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
    ]
    apk_path = _make_apk(perms)
    app_id = os.path.splitext(os.path.basename(apk_path))[0]

    # Temporarily override the upload dir so the module finds the file
    import modules.permissions as pmod
    original_dir = pmod.APK_UPLOAD_DIR
    pmod.APK_UPLOAD_DIR = os.path.dirname(apk_path)
    try:
        result = analyze_permissions(app_id)
    finally:
        pmod.APK_UPLOAD_DIR = original_dir
        os.unlink(apk_path)

    assert "permissions" in result
    assert "breakdown" in result
    bd = result["breakdown"]
    assert "necessary" in bd
    assert "optional"  in bd
    assert "excessive" in bd

    # Every item must have the three frontend-required keys
    for item in result["permissions"]:
        assert "name"  in item
        assert "risk"  in item
        assert "label" in item
        assert item["risk"]  in ("low", "med", "high")
        assert item["label"] in ("Necessary", "Optional", "Excessive")


# ══════════════════════════════════════════════════════════════════════════
# TEST 8 — analyze_permissions: breakdown counts are consistent
# ══════════════════════════════════════════════════════════════════════════
def test_analyze_permissions_breakdown_counts():
    perms = [
        "android.permission.INTERNET",            # Necessary
        "android.permission.CAMERA",              # Excessive (High impact)
        "android.permission.BLUETOOTH_CONNECT",   # Optional  (Medium impact)
    ]
    apk_path = _make_apk(perms)
    app_id = os.path.splitext(os.path.basename(apk_path))[0]

    import modules.permissions as pmod
    original_dir = pmod.APK_UPLOAD_DIR
    pmod.APK_UPLOAD_DIR = os.path.dirname(apk_path)
    try:
        result = analyze_permissions(app_id)
    finally:
        pmod.APK_UPLOAD_DIR = original_dir
        os.unlink(apk_path)

    bd = result["breakdown"]
    total = bd["necessary"] + bd["optional"] + bd["excessive"]
    assert total == len(result["permissions"]), \
        "Breakdown counts must sum to total number of permissions"


# ══════════════════════════════════════════════════════════════════════════
# TEST 9 — analyze_permissions: raises FileNotFoundError for missing APK
# ══════════════════════════════════════════════════════════════════════════
def test_analyze_permissions_missing_apk():
    import modules.permissions as pmod
    original_dir = pmod.APK_UPLOAD_DIR
    pmod.APK_UPLOAD_DIR = "/nonexistent_dir"
    try:
        with pytest.raises(FileNotFoundError):
            analyze_permissions("ghost_app_id")
    finally:
        pmod.APK_UPLOAD_DIR = original_dir


# ══════════════════════════════════════════════════════════════════════════
# TEST 10 — PERMISSIONS_DB: every entry has required keys
# ══════════════════════════════════════════════════════════════════════════
def test_permissions_db_schema():
    required_keys = {"protection_level", "privacy_impact", "category",
                     "description", "recommendation"}
    for name, info in PERMISSIONS_DB.items():
        missing = required_keys - info.keys()
        assert not missing, f"Permission '{name}' is missing keys: {missing}"

    valid_levels  = {"normal", "dangerous", "special"}
    valid_impacts = {"Low", "Medium", "High"}
    for name, info in PERMISSIONS_DB.items():
        assert info["protection_level"] in valid_levels, \
            f"'{name}' has invalid protection_level: {info['protection_level']}"
        assert info["privacy_impact"] in valid_impacts, \
            f"'{name}' has invalid privacy_impact: {info['privacy_impact']}"
