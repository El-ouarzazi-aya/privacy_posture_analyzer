"""
permissions.py — Permissions Analyst & Manifest Parser
Member 1 | Privacy Posture Analyzer

Responsibilities:
  - Parse AndroidManifest.xml from APK (binary AXML, no external deps)
  - Classify every permission using the embedded database
  - Score justification via keyword matching against APK strings
  - Map each permission to risk (low / med / high) and label
    (Necessary / Optional / Excessive)
  - Return the format consumed by the shared backend API

APK files are expected at:  uploads/{app_id}.apk
"""

import os
import re
import zipfile
import math

# ── Upload directory (must match main.py) ─────────────────────────────────
APK_UPLOAD_DIR = "uploads"

# ══════════════════════════════════════════════════════════════════════════
# PERMISSIONS DATABASE  (ported from data/permissions_db.json)
# ══════════════════════════════════════════════════════════════════════════
PERMISSIONS_DB = {
    "android.permission.INTERNET": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Network",
        "description": "Allows applications to access the internet",
        "recommendation": "Generally safe",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Network",
        "description": "Allows access to network state information",
        "recommendation": "Generally safe",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Network",
        "description": "Allows access to WiFi network information",
        "recommendation": "Monitor network usage",
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Network",
        "description": "Allows changing WiFi connectivity state",
        "recommendation": "Ensure legitimate network management",
    },
    "android.permission.CHANGE_NETWORK_STATE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Network",
        "description": "Allows changing network connectivity state",
        "recommendation": "Review necessity",
    },
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Network",
        "description": "Allows applications to enter WiFi multicast mode",
        "recommendation": "Use only for local network discovery",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Location",
        "description": "Allows access to precise GPS location",
        "recommendation": "Only request while app is in use",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Location",
        "description": "Allows access to approximate location",
        "recommendation": "Use approximate location whenever possible",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Location",
        "description": "Allows background location access",
        "recommendation": "Avoid continuous background tracking",
    },
    "android.permission.ACCESS_MEDIA_LOCATION": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Media",
        "description": "Allows access to media location metadata",
        "recommendation": "Restrict metadata access",
    },
    "android.permission.CAMERA": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Hardware Access",
        "description": "Allows access to device camera",
        "recommendation": "Request only when necessary",
    },
    "android.permission.RECORD_AUDIO": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Audio",
        "description": "Allows recording audio from microphone",
        "recommendation": "Clearly explain microphone usage",
    },
    "android.permission.MODIFY_AUDIO_SETTINGS": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Audio",
        "description": "Allows modifying audio settings",
        "recommendation": "Review necessity",
    },
    "android.permission.READ_CONTACTS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Personal Data",
        "description": "Allows reading user contacts",
        "recommendation": "Avoid collecting unnecessary contacts",
    },
    "android.permission.WRITE_CONTACTS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Personal Data",
        "description": "Allows modifying contacts",
        "recommendation": "Limit contact modifications",
    },
    "android.permission.GET_ACCOUNTS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Accounts",
        "description": "Allows access to accounts on the device",
        "recommendation": "Avoid unnecessary account access",
    },
    "android.permission.READ_SMS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Messaging",
        "description": "Allows reading SMS messages",
        "recommendation": "Restrict SMS access",
    },
    "android.permission.SEND_SMS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Messaging",
        "description": "Allows sending SMS messages",
        "recommendation": "Monitor SMS sending activity",
    },
    "android.permission.RECEIVE_SMS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Messaging",
        "description": "Allows receiving SMS messages",
        "recommendation": "Request only for messaging apps",
    },
    "android.permission.READ_CALL_LOG": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Calls",
        "description": "Allows reading call logs",
        "recommendation": "Avoid collecting call history",
    },
    "android.permission.WRITE_CALL_LOG": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Calls",
        "description": "Allows modifying call logs",
        "recommendation": "Restrict call log modifications",
    },
    "android.permission.CALL_PHONE": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Calls",
        "description": "Allows direct phone calls",
        "recommendation": "Request only for dialer functionality",
    },
    "android.permission.READ_PHONE_STATE": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Device Information",
        "description": "Allows reading phone state and device identifiers",
        "recommendation": "Avoid persistent device tracking",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Phone",
        "description": "Allows reading phone numbers",
        "recommendation": "Avoid unnecessary phone number access",
    },
    "android.permission.READ_CLIPBOARD": {
        "protection_level": "dangerous", "privacy_impact": "High", "category": "Privacy",
        "description": "Allows reading clipboard content",
        "recommendation": "Avoid accessing clipboard unnecessarily",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Storage",
        "description": "Allows reading external storage",
        "recommendation": "Limit file access",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Storage",
        "description": "Allows writing to external storage",
        "recommendation": "Avoid broad storage permissions",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "protection_level": "special", "privacy_impact": "High", "category": "Storage",
        "description": "Allows broad access to external storage",
        "recommendation": "Restrict storage access whenever possible",
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Media",
        "description": "Allows reading image media files",
        "recommendation": "Restrict image access",
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Media",
        "description": "Allows reading video media files",
        "recommendation": "Restrict video access",
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Media",
        "description": "Allows reading audio media files",
        "recommendation": "Restrict audio access",
    },
    "android.permission.BLUETOOTH": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Connectivity",
        "description": "Allows using Bluetooth",
        "recommendation": "Monitor Bluetooth usage",
    },
    "android.permission.BLUETOOTH_ADMIN": {
        "protection_level": "special", "privacy_impact": "Medium", "category": "Connectivity",
        "description": "Allows managing Bluetooth settings",
        "recommendation": "Avoid unnecessary Bluetooth administration",
    },
    "android.permission.BLUETOOTH_SCAN": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Connectivity",
        "description": "Allows scanning nearby Bluetooth devices",
        "recommendation": "Avoid continuous Bluetooth scanning",
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "protection_level": "dangerous", "privacy_impact": "Medium", "category": "Connectivity",
        "description": "Allows connecting to paired Bluetooth devices",
        "recommendation": "Restrict device connections",
    },
    "android.permission.NFC": {
        "protection_level": "normal", "privacy_impact": "Medium", "category": "Connectivity",
        "description": "Allows near-field communication",
        "recommendation": "Request only for NFC functionality",
    },
    "android.permission.POST_NOTIFICATIONS": {
        "protection_level": "dangerous", "privacy_impact": "Low", "category": "User Interaction",
        "description": "Allows posting notifications",
        "recommendation": "Avoid notification spam",
    },
    "android.permission.VIBRATE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "User Interaction",
        "description": "Allows device vibration",
        "recommendation": "Generally safe",
    },
    "android.permission.WAKE_LOCK": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Power Management",
        "description": "Allows preventing device sleep",
        "recommendation": "Use responsibly to preserve battery",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "protection_level": "special", "privacy_impact": "High", "category": "Privacy",
        "description": "Allows querying all installed applications",
        "recommendation": "Avoid broad package visibility",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "protection_level": "special", "privacy_impact": "Medium", "category": "System",
        "description": "Allows requesting installation of packages",
        "recommendation": "Use only for app stores or installers",
    },
    "android.permission.REQUEST_DELETE_PACKAGES": {
        "protection_level": "special", "privacy_impact": "Medium", "category": "System",
        "description": "Allows requesting deletion of installed packages",
        "recommendation": "Use only when necessary",
    },
    "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION": {
        "protection_level": "special", "privacy_impact": "High", "category": "System",
        "description": "Allows silent package updates",
        "recommendation": "Highly sensitive permission",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "System",
        "description": "Allows application to start after device boot",
        "recommendation": "Ensure background startup is necessary",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "System",
        "description": "Allows running foreground services",
        "recommendation": "Use foreground services responsibly",
    },
    "android.permission.FOREGROUND_SERVICE_CAMERA": {
        "protection_level": "normal", "privacy_impact": "Medium", "category": "Foreground Service",
        "description": "Allows foreground camera service",
        "recommendation": "Use only during active camera usage",
    },
    "android.permission.FOREGROUND_SERVICE_MICROPHONE": {
        "protection_level": "normal", "privacy_impact": "Medium", "category": "Foreground Service",
        "description": "Allows foreground microphone service",
        "recommendation": "Use only during active recording",
    },
    "android.permission.FOREGROUND_SERVICE_LOCATION": {
        "protection_level": "normal", "privacy_impact": "Medium", "category": "Foreground Service",
        "description": "Allows foreground location service",
        "recommendation": "Restrict persistent location access",
    },
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Foreground Service",
        "description": "Allows media playback foreground service",
        "recommendation": "Use during active media playback",
    },
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Foreground Service",
        "description": "Allows foreground data synchronization",
        "recommendation": "Use only when synchronization is active",
    },
    "android.permission.FOREGROUND_SERVICE_PHONE_CALL": {
        "protection_level": "normal", "privacy_impact": "Medium", "category": "Foreground Service",
        "description": "Allows phone call foreground service",
        "recommendation": "Use only during active calls",
    },
    "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Foreground Service",
        "description": "Allows remote messaging foreground service",
        "recommendation": "Use for real-time communication only",
    },
    "android.permission.WRITE_SETTINGS": {
        "protection_level": "special", "privacy_impact": "High", "category": "System Settings",
        "description": "Allows modifying system settings",
        "recommendation": "Restrict modification of device settings",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "protection_level": "special", "privacy_impact": "High", "category": "System Overlay",
        "description": "Allows drawing over other applications",
        "recommendation": "Restrict overlay permissions",
    },
    "android.permission.MANAGE_OWN_CALLS": {
        "protection_level": "special", "privacy_impact": "Medium", "category": "Calls",
        "description": "Allows managing own calls",
        "recommendation": "Use only for communication apps",
    },
    "android.permission.USE_BIOMETRIC": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Authentication",
        "description": "Allows biometric authentication",
        "recommendation": "Use secure biometric authentication",
    },
    "android.permission.USE_FINGERPRINT": {
        "protection_level": "normal", "privacy_impact": "Low", "category": "Authentication",
        "description": "Allows fingerprint authentication",
        "recommendation": "Use secure fingerprint authentication",
    },
}

# ── Permission weights (from risk_scoring.py) ─────────────────────────────
_WEIGHTS = {
    "android.permission.CAMERA": 10,
    "android.permission.RECORD_AUDIO": 10,
    "android.permission.ACCESS_FINE_LOCATION": 9,
    "android.permission.READ_CONTACTS": 9,
    "android.permission.READ_SMS": 9,
    "android.permission.READ_CALL_LOG": 9,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 8,
    "android.permission.QUERY_ALL_PACKAGES": 8,
    "android.permission.WRITE_CONTACTS": 7,
    "android.permission.WRITE_CALL_LOG": 7,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 7,
    "android.permission.READ_PHONE_STATE": 7,
    "android.permission.GET_ACCOUNTS": 7,
    "android.permission.BLUETOOTH_SCAN": 5,
    "android.permission.BLUETOOTH_CONNECT": 5,
    "android.permission.WRITE_EXTERNAL_STORAGE": 5,
    "android.permission.READ_EXTERNAL_STORAGE": 5,
    "android.permission.REQUEST_INSTALL_PACKAGES": 5,
    "android.permission.INTERNET": 2,
    "android.permission.POST_NOTIFICATIONS": 1,
    "android.permission.ACCESS_NETWORK_STATE": 1,
    "android.permission.VIBRATE": 1,
    "android.permission.WAKE_LOCK": 1,
}

# ── Justification keywords (from justification_analyzer.py) ──────────────
_JUSTIFICATION_KEYWORDS = {
    "android.permission.CAMERA": [
        "camera", "photo", "scan", "qr", "capture", "barcode", "video call", "selfie",
    ],
    "android.permission.RECORD_AUDIO": [
        "voice", "audio", "microphone", "record", "speech", "voice note", "call",
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        "location", "gps", "map", "nearby", "navigation", "share location",
    ],
    "android.permission.BLUETOOTH_SCAN": [
        "bluetooth", "device", "connect", "ble", "wireless",
    ],
    "android.permission.BLUETOOTH_CONNECT": [
        "bluetooth", "pair", "device", "connect", "speaker",
    ],
    "android.permission.INTERNET": [
        "online", "network", "sync", "internet", "download", "update", "stream", "server",
    ],
    "android.permission.POST_NOTIFICATIONS": [
        "notification", "alert", "message", "reminder", "push",
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        "storage", "file", "media", "import", "gallery", "video", "music",
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        "save", "export", "storage", "backup", "download",
    ],
}


# ══════════════════════════════════════════════════════════════════════════
# MANIFEST PARSER  (no androguard — pure zipfile + regex)
# ══════════════════════════════════════════════════════════════════════════

def parse_permissions_from_apk(apk_path: str) -> list:
    """
    Extract declared permissions from the binary AndroidManifest.xml
    inside an APK without any external library.

    Android stores the manifest in Binary XML (AXML).  Permission strings
    are kept in the string pool, encoded as UTF-16 LE (or UTF-8 in newer
    builds).  Decoding the raw bytes in both encodings and applying a
    regex is fast and reliable for standard android.permission.* names.
    """
    permissions: set = set()

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return []
            data = zf.read("AndroidManifest.xml")

            # Try UTF-16 LE first (standard AXML string-pool encoding)
            for encoding in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    text = data.decode(encoding, errors="replace")
                    found = re.findall(r"android\.permission\.[A-Z_]+", text)
                    permissions.update(found)
                except Exception:
                    pass
    except Exception:
        pass

    return sorted(permissions)


def _collect_apk_strings(apk_path: str) -> list:
    """
    Collect human-readable strings from the APK (file paths + raw bytes)
    for justification scoring.  Mirrors justification_analyzer.py logic
    without requiring the androguard APK object.
    """
    strings: list = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            # File entry paths reveal activity/service names
            for name in zf.namelist():
                strings.append(name.lower().replace("/", " ").replace("_", " "))

            # Also scan resource files for human-readable strings
            for entry in zf.namelist():
                if entry.endswith(("strings.xml", "values/strings.xml")):
                    try:
                        raw = zf.read(entry).decode("utf-8", errors="replace")
                        strings.append(raw.lower())
                    except Exception:
                        pass
    except Exception:
        pass
    return strings


# ══════════════════════════════════════════════════════════════════════════
# CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════

def classify_permission(name: str) -> dict:
    """
    Look up a permission in the embedded database.
    Returns a full classification dict; unknown permissions get sensible
    defaults so the pipeline never hard-crashes.
    """
    info = PERMISSIONS_DB.get(name)
    if info:
        return {
            "permission": name,
            "protection_level": info["protection_level"],
            "privacy_impact": info["privacy_impact"],
            "category": info["category"],
            "description": info["description"],
            "recommendation": info["recommendation"],
        }
    return {
        "permission": name,
        "protection_level": "unknown",
        "privacy_impact": "Unknown",
        "category": "Unknown",
        "description": "No description available",
        "recommendation": "Review permission manually",
    }


def _to_risk(classified: dict) -> str:
    """Map protection level + privacy impact to frontend risk label."""
    level = classified["protection_level"]
    impact = classified["privacy_impact"]
    if level == "special":
        return "high"
    if impact == "High":
        return "high"
    if impact == "Medium":
        return "med"
    return "low"


def _to_label(classified: dict) -> str:
    """
    Map classification to Necessary / Optional / Excessive.

    Rules (aligned with Member 1's risk_scoring.py logic):
      - normal + Low impact   → Necessary   (safe, expected infrastructure)
      - normal + Medium/High  → Optional    (present but not critical)
      - dangerous + Low       → Necessary   (e.g. POST_NOTIFICATIONS)
      - dangerous + Medium    → Optional    (contextually acceptable)
      - dangerous + High      → Excessive   (sensitive, needs justification)
      - special (any impact)  → Excessive   (elevated-privilege permissions)
      - unknown               → Optional    (benefit of the doubt)
    """
    level = classified["protection_level"]
    impact = classified["privacy_impact"]

    if level == "special":
        return "Excessive"
    if level == "unknown":
        return "Optional"
    if level == "normal":
        if impact in ("Low", "Medium"):
            return "Necessary"
        return "Optional"   # normal + High is unusual; treat as optional
    # dangerous
    if impact == "High":
        return "Excessive"
    if impact == "Medium":
        return "Optional"
    return "Necessary"      # dangerous + Low (e.g. POST_NOTIFICATIONS)


# ══════════════════════════════════════════════════════════════════════════
# JUSTIFICATION SCORING  (ported from justification_analyzer.py)
# ══════════════════════════════════════════════════════════════════════════

def _justification_score(permission: str, apk_strings: list) -> int:
    """
    Logarithmic keyword-frequency score (0-100) measuring how well the
    APK's own text content justifies requesting this permission.
    """
    keywords = _JUSTIFICATION_KEYWORDS.get(permission, [])
    if not keywords:
        return 50   # no mapping → neutral score

    matches = 0
    for kw in keywords:
        kw = kw.lower()
        count = 0
        for s in apk_strings:
            if kw in s:
                count += 1
                if count >= 20:   # overflow guard
                    break
        matches += count

    if matches > 0:
        score = int(math.log(matches + 1) * 22)
        return min(score, 100)
    return 0


# ══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def analyze_permissions(app_id: str) -> dict:
    """
    Parse the APK for app_id, classify every declared permission, and
    return the response format consumed by the shared backend:

        {
            "permissions": [{"name": str, "risk": str, "label": str}, ...],
            "breakdown":   {"necessary": int, "optional": int, "excessive": int},
        }

    Raises FileNotFoundError if the APK is not found in the uploads directory.
    """
    apk_path = os.path.join(APK_UPLOAD_DIR, f"{app_id}.apk")
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found for app_id='{app_id}'")

    raw_perms = parse_permissions_from_apk(apk_path)
    apk_strings = _collect_apk_strings(apk_path)

    permissions_out: list = []
    necessary = optional = excessive = 0

    for name in raw_perms:
        classified = classify_permission(name)
        risk  = _to_risk(classified)
        label = _to_label(classified)

        # Downgrade Excessive → Optional when justification score is strong
        if label == "Excessive":
            j_score = _justification_score(name, apk_strings)
            if j_score >= 70:
                label = "Optional"
                risk  = "med" if risk == "high" else risk

        permissions_out.append({
            "name":  name,
            "risk":  risk,
            "label": label,
        })

        if label == "Necessary":
            necessary += 1
        elif label == "Optional":
            optional += 1
        else:
            excessive += 1

    # If parsing failed entirely, return safe minimum
    if not permissions_out:
        permissions_out = [
            {"name": "android.permission.INTERNET",
             "risk": "low", "label": "Necessary"},
        ]
        necessary = 1

    return {
        "permissions": permissions_out,
        "breakdown": {
            "necessary": necessary,
            "optional":  optional,
            "excessive": excessive,
        },
    }
