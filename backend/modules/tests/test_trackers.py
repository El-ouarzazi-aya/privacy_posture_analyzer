"""
test_trackers.py — Unit Tests for SDK/Tracker Detection Module
Member 2 | Privacy Posture Analyzer
Run with: pytest tests/test_trackers.py -v
"""

import io
import zipfile
import pytest
from unittest.mock import MagicMock, patch
from modules.trackers import (
    _extract_file_entries,
    _scan_for_trackers,
    _persist_trackers,
    TRACKER_DB,
)


# ---------------------------------------------------------------------------
# Helpers — build fake APK (ZIP) files in memory
# ---------------------------------------------------------------------------

def _make_fake_apk(file_paths: list[str]) -> bytes:
    """
    Create an in-memory ZIP archive whose entries are the given file_paths.
    Each entry has empty content — we only care about the names.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in file_paths:
            zf.writestr(path, "")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Test 1 — _extract_file_entries returns normalised, lower-cased dot paths
# ---------------------------------------------------------------------------

def test_extract_file_entries_normalises_paths(tmp_path):
    """
    File paths inside the APK are slash-separated and mixed-case.
    _extract_file_entries must return them lower-cased with slashes
    converted to dots so signature matching works uniformly.
    """
    apk_bytes = _make_fake_apk([
        "com/Facebook/Ads/FacebookAds.class",
        "META-INF/MANIFEST.MF",
        "res/layout/main.xml",
    ])
    apk_file = tmp_path / "test.apk"
    apk_file.write_bytes(apk_bytes)

    entries = _extract_file_entries(str(apk_file))

    assert "com.facebook.ads.facebookads.class" in entries
    assert "meta-inf.manifest.mf" in entries
    assert "res.layout.main.xml" in entries


# ---------------------------------------------------------------------------
# Test 2 — _scan_for_trackers detects known SDKs
# ---------------------------------------------------------------------------

def test_scan_detects_known_sdks():
    """
    Given APK entries that contain known package signatures,
    _scan_for_trackers must return the correct matched tracker dicts.
    """
    fake_entries = [
        "com.facebook.ads.interstitialadactivity",           # Meta Audience Network
                                                             # also triggers Facebook SDK (com.facebook is a substring)
        "com.google.firebase.analytics.firebaseanalytics",   # Firebase Analytics
        "com.crashlytics.android.answers",                   # Crashlytics
        "some.random.unknown.library.class",                 # no match
    ]

    matched = _scan_for_trackers(fake_entries)
    names = [t["sdk_name"] for t in matched]

    assert "Meta Audience Network" in names
    assert "Facebook SDK" in names        # com.facebook is a substring of com.facebook.ads
    assert "Firebase Analytics" in names
    assert "Crashlytics" in names
    assert len(matched) == 4              # unknown library must not appear
    assert "some.random.unknown.library" not in names


# ---------------------------------------------------------------------------
# Test 3 — _scan_for_trackers deduplicates repeated signature hits
# ---------------------------------------------------------------------------

def test_scan_deduplicates_multiple_hits():
    """
    The same SDK signature may appear in many files inside one APK.
    _scan_for_trackers must return each SDK exactly once regardless of
    how many entries match it.
    """
    fake_entries = [
        "com.adjust.sdk.adjust",
        "com.adjust.sdk.activityhandler",
        "com.adjust.sdk.packagebuilder",
        "com.adjust.sdk.requesthandler",
    ]

    matched = _scan_for_trackers(fake_entries)
    names = [t["sdk_name"] for t in matched]

    assert names.count("Adjust") == 1
    assert len(matched) == 1


# ---------------------------------------------------------------------------
# Test 4 — _scan_for_trackers returns empty list for clean APK
# ---------------------------------------------------------------------------

def test_scan_returns_empty_for_clean_apk():
    """
    An APK with no known tracker signatures must produce an empty list,
    not an error. This mirrors the UnCrackable-Level1 result we saw live.
    """
    clean_entries = [
        "res.layout.activity_main.xml",
        "classes.dex",
        "androidmanifest.xml",
        "meta-inf.cert.rsa",
    ]

    matched = _scan_for_trackers(clean_entries)

    assert matched == []


# ---------------------------------------------------------------------------
# Test 5 — _persist_trackers writes correct rows to the database
# ---------------------------------------------------------------------------

def test_persist_trackers_writes_to_db():
    """
    _persist_trackers must call db.add() once per matched tracker,
    call db.commit() exactly once, and return one ORM object per tracker.
    """
    mock_db = MagicMock()

    # Simulate db.refresh() assigning an id to each object
    def fake_refresh(obj):
        obj.id = 99

    mock_db.refresh.side_effect = fake_refresh

    trackers_to_save = [
        {
            "sdk_name": "Facebook SDK",
            "category": "Social",
            "risk_score": 80,
            "data_collected": "User profile, social graph, device info",
        },
        {
            "sdk_name": "AdMob",
            "category": "Advertising",
            "risk_score": 80,
            "data_collected": "Ad targeting signals, device ID",
        },
    ]

    with patch("modules.trackers.Tracker") as MockTracker:
        # Make Tracker() return a fresh MagicMock each call
        MockTracker.side_effect = lambda **kwargs: MagicMock(**kwargs)

        result = _persist_trackers(mock_db, audit_id=1, matched_trackers=trackers_to_save)

    assert mock_db.add.call_count == 2
    mock_db.commit.assert_called_once()
    assert mock_db.refresh.call_count == 2
    assert len(result) == 2
