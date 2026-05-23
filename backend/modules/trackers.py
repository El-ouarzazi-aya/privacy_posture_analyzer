"""
trackers.py — SDK/Tracker Detection Module
Member 2 | Privacy Posture Analyzer
POST /analyze/trackers/{app_id}

Deep scanner: handles standard APKs, XAPK bundles, split APKs,
and wrapper installers by recursively scanning all nested archives.
"""

import zipfile
import io
import os
from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Tracker, Audit

router = APIRouter()

TRACKER_DB = [
    {"signature": "com.facebook.ads",               "sdk_name": "Meta Audience Network",    "category": "Advertising", "risk_score": 85, "data_collected": "Device ID, location, browsing behaviour, purchase history, ad interaction data"},
    {"signature": "com.facebook",                   "sdk_name": "Facebook SDK",             "category": "Social",      "risk_score": 80, "data_collected": "User profile, social graph, device info, app events, login tokens"},
    {"signature": "com.google.firebase.analytics",  "sdk_name": "Firebase Analytics",       "category": "Analytics",   "risk_score": 60, "data_collected": "App usage events, session duration, device model, OS version, country"},
    {"signature": "com.google.firebase",            "sdk_name": "Firebase (General)",       "category": "Analytics",   "risk_score": 58, "data_collected": "Cloud messaging, remote config, app indexing, authentication tokens"},
    {"signature": "com.crashlytics",                "sdk_name": "Crashlytics",              "category": "Crash",       "risk_score": 30, "data_collected": "Crash stack traces, device state at crash, OS version, app version"},
    {"signature": "com.adjust",                     "sdk_name": "Adjust",                   "category": "Analytics",   "risk_score": 75, "data_collected": "Install source, ad campaign attribution, device fingerprint, IP address"},
    {"signature": "com.appsflyer",                  "sdk_name": "AppsFlyer",                "category": "Analytics",   "risk_score": 75, "data_collected": "Attribution data, in-app events, revenue, device identifiers, referrer"},
    {"signature": "com.google.android.gms.ads",     "sdk_name": "AdMob",                    "category": "Advertising", "risk_score": 80, "data_collected": "Ad targeting signals, device ID, location (coarse), interest categories"},
    {"signature": "com.unity3d.ads",                "sdk_name": "Unity Ads",                "category": "Advertising", "risk_score": 70, "data_collected": "Device ID, game progress, ad view data, IDFA/GAID, country"},
    {"signature": "com.stripe",                     "sdk_name": "Stripe",                   "category": "Payment",     "risk_score": 55, "data_collected": "Payment card metadata (tokenised), billing address, transaction identifiers"},
    {"signature": "io.branch",                      "sdk_name": "Branch",                   "category": "Analytics",   "risk_score": 65, "data_collected": "Deep-link attribution, device fingerprint, referrer URL, install time"},
    {"signature": "com.mixpanel",                   "sdk_name": "Mixpanel",                 "category": "Analytics",   "risk_score": 60, "data_collected": "User events, funnels, retention metrics, device type, custom properties"},
    {"signature": "com.amplitude",                  "sdk_name": "Amplitude",                "category": "Analytics",   "risk_score": 60, "data_collected": "Behavioural events, user properties, session data, revenue metrics"},
    {"signature": "com.segment",                    "sdk_name": "Segment",                  "category": "Analytics",   "risk_score": 65, "data_collected": "User identity, event streams forwarded to third-party destinations, traits"},
    {"signature": "com.onesignal",                  "sdk_name": "OneSignal",                "category": "Analytics",   "risk_score": 55, "data_collected": "Push notification tokens, device ID, notification open/click events"},
    {"signature": "com.applovin",                   "sdk_name": "AppLovin",                 "category": "Advertising", "risk_score": 82, "data_collected": "GAID/IDFA, precise location, user interests, app install history"},
    {"signature": "com.ironsource",                 "sdk_name": "IronSource",               "category": "Advertising", "risk_score": 78, "data_collected": "Ad engagement, device ID, connection type, mediation waterfall data"},
    {"signature": "com.chartboost",                 "sdk_name": "Chartboost",               "category": "Advertising", "risk_score": 72, "data_collected": "GAID, gameplay session info, ad impression data, app version"},
    {"signature": "com.vungle",                     "sdk_name": "Vungle",                   "category": "Advertising", "risk_score": 72, "data_collected": "Device ID, video ad view metrics, network type, locale"},
    {"signature": "com.mopub",                      "sdk_name": "MoPub",                    "category": "Advertising", "risk_score": 76, "data_collected": "Ad requests, device fingerprint, location (coarse), targeting segments"},
    {"signature": "com.twitter",                    "sdk_name": "Twitter SDK",              "category": "Social",      "risk_score": 70, "data_collected": "Twitter account linkage, tweet/share events, device info, ad conversion"},
    {"signature": "com.google.android.gms.analytics","sdk_name": "Google Analytics (Legacy)","category": "Analytics",  "risk_score": 58, "data_collected": "Screen views, session data, device category, geographic region"},
    {"signature": "com.snap",                       "sdk_name": "Snap SDK",                 "category": "Social",      "risk_score": 68, "data_collected": "Snap account linkage, share events, device info, story impressions"},
    {"signature": "com.braze",                      "sdk_name": "Braze",                    "category": "Analytics",   "risk_score": 62, "data_collected": "User profiles, push/in-app engagement, purchase events, custom attributes"},
    # Extra signatures to catch more real-world SDKs
    {"signature": "com.google.android.datatransport","sdk_name": "Google Data Transport",   "category": "Analytics",   "risk_score": 55, "data_collected": "Batched event data sent to Google backend services"},
    {"signature": "com.google.android.gms",         "sdk_name": "Google Play Services",     "category": "Analytics",   "risk_score": 45, "data_collected": "Device attestation, location, push tokens, account info"},
    {"signature": "io.intercom",                    "sdk_name": "Intercom",                 "category": "Analytics",   "risk_score": 58, "data_collected": "User identity, support conversations, device info, app events"},
    {"signature": "com.datadog",                    "sdk_name": "Datadog",                  "category": "Crash",       "risk_score": 35, "data_collected": "Performance metrics, error traces, network requests timing"},
    {"signature": "com.newrelic",                   "sdk_name": "New Relic",                "category": "Crash",       "risk_score": 35, "data_collected": "Crash reports, HTTP request data, device performance metrics"},
    {"signature": "com.tiktok",                     "sdk_name": "TikTok SDK",               "category": "Advertising", "risk_score": 88, "data_collected": "Device fingerprint, clipboard content, location, behavioural profile"},
    {"signature": "com.bytedance",                  "sdk_name": "ByteDance SDK",            "category": "Advertising", "risk_score": 88, "data_collected": "Device ID, usage patterns, ad targeting data, keystroke timing"},
    {"signature": "com.spotify",                    "sdk_name": "Spotify SDK",              "category": "Analytics",   "risk_score": 50, "data_collected": "Playback events, device info, account linkage"},
    {"signature": "com.microsoft.appcenter",        "sdk_name": "App Center (Microsoft)",   "category": "Crash",       "risk_score": 32, "data_collected": "Crash reports, diagnostics, device metadata"},
    {"signature": "com.bugsnag",                    "sdk_name": "Bugsnag",                  "category": "Crash",       "risk_score": 30, "data_collected": "Error reports, breadcrumbs, device and app state"},
    {"signature": "com.singular",                   "sdk_name": "Singular",                 "category": "Analytics",   "risk_score": 70, "data_collected": "Attribution, SKAdNetwork, device ID, revenue events"},
    {"signature": "com.kochava",                    "sdk_name": "Kochava",                  "category": "Analytics",   "risk_score": 72, "data_collected": "Device fingerprint, install attribution, in-app events"},
]

APK_UPLOAD_DIR = "uploads"


def _get_apk_path(app_id: str) -> str:
    path = os.path.join(APK_UPLOAD_DIR, f"{app_id}.apk")
    if not os.path.exists(path):
        raise FileNotFoundError(f"APK file not found for app_id={app_id}")
    return path


def _collect_entries_from_zip(zf: zipfile.ZipFile, depth: int = 0, max_depth: int = 3) -> list[str]:
    """
    Recursively collect all file path strings from a ZipFile.
    - Converts slash-separated paths to dot-separated lowercase strings.
    - Recurses into nested .apk / .jar / .aar / .zip up to max_depth.
    - Also reads strings directly from .dex files to catch obfuscated SDKs.
    """
    entries: list[str] = []
    if depth > max_depth:
        return entries

    names = zf.namelist()

    # 1. Add all file paths as dot-separated strings
    for name in names:
        entries.append(name.lower().replace("/", "."))

    # 2. Recurse into nested archives
    for name in names:
        lower = name.lower()
        if lower.endswith((".apk", ".jar", ".aar", ".zip")):
            try:
                data = zf.read(name)
                with zipfile.ZipFile(io.BytesIO(data)) as inner_zf:
                    entries.extend(_collect_entries_from_zip(inner_zf, depth + 1, max_depth))
            except Exception:
                pass

        # 3. Scan raw bytes of .dex files for package name strings
        elif lower.endswith(".dex"):
            try:
                data = zf.read(name)
                entries.extend(_extract_strings_from_dex(data))
            except Exception:
                pass

    return entries


def _extract_strings_from_dex(data: bytes) -> list[str]:
    """
    Extract human-readable strings from a DEX binary that look like
    Java package names (contain dots and slashes, no spaces).
    This catches SDKs even when their class files are merged/obfuscated.
    """
    results = []
    try:
        # DEX stores class names as null-terminated UTF-8 strings with L...;  format
        # We scan for patterns like Lcom/facebook/... or com/google/...
        text = data.decode("utf-8", errors="ignore")
        import re
        # Match Java class path patterns e.g. Lcom/facebook/ads/AdActivity;
        patterns = re.findall(r'L([a-z][a-z0-9_/]{4,}[a-z0-9_]);', text)
        for p in patterns:
            results.append(p.replace("/", "."))
        # Also match plain package strings like com.adjust.sdk
        plain = re.findall(r'(?<![a-zA-Z])((?:[a-z][a-z0-9_]+\.){2,}[a-z][a-z0-9_]+)', text)
        results.extend(plain)
    except Exception:
        pass
    return results


def _extract_file_entries(apk_path: str) -> list[str]:
    """
    Main entry point for APK scanning.
    Opens the outer APK and delegates to the recursive collector.
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            return _collect_entries_from_zip(zf, depth=0, max_depth=3)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"File is not a valid APK/ZIP archive: {exc}")


def _scan_for_trackers(entries: list[str]) -> list[dict]:
    matched: dict[str, dict] = {}
    for tracker in TRACKER_DB:
        sig = tracker["signature"].lower()
        for entry in entries:
            if sig in entry:
                if tracker["sdk_name"] not in matched:
                    matched[tracker["sdk_name"]] = tracker
                break
    return list(matched.values())


def _persist_trackers(db: Session, audit_id: int, matched_trackers: list[dict]) -> list[Tracker]:
    orm_objects: list[Tracker] = []
    for t in matched_trackers:
        obj = Tracker(
            audit_id=audit_id,
            sdk_name=t["sdk_name"],
            category=t["category"],
            risk_score=t["risk_score"],
            data_collected=t["data_collected"],
        )
        db.add(obj)
        orm_objects.append(obj)
    db.commit()
    for obj in orm_objects:
        db.refresh(obj)
    return orm_objects


@router.post("/analyze/trackers/{app_id}")
def analyze_trackers(app_id: str):
    """
    Deep-scan the APK for the given app_id.
    Handles standard APKs, XAPK bundles, split APKs, and wrapper installers.
    """
    db: Session = SessionLocal()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if audit is None:
            raise HTTPException(status_code=404, detail=f"No audit record found for app_id='{app_id}'.")
        try:
            apk_path = _get_apk_path(app_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        try:
            entries = _extract_file_entries(apk_path)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        matched = _scan_for_trackers(entries)
        saved = _persist_trackers(db, audit.id, matched)

        result = [
            {"id": obj.id, "audit_id": obj.audit_id, "sdk_name": obj.sdk_name,
             "category": obj.category, "risk_score": obj.risk_score,
             "data_collected": obj.data_collected}
            for obj in saved
        ]
        return {"app_id": app_id, "total_trackers_found": len(result), "trackers": result}
    finally:
        db.close()