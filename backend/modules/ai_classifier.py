# ai_classifier.py
# Bridges the AI engine (classifier, scorer, checklist) to the main backend
# This module is called by main.py's /analyze/ai/{app_id} endpoint
# It takes real tracker and permission data from the database
# and returns AI analysis in the exact format the frontend expects

import sys
import os

# Make sure Python can find our modules
sys.path.append(os.path.dirname(__file__))

from classifier import classify_multiple_permissions
from scorer import calculate_score
from checklist import generate_checklist


def run_ai_analysis(app_id: str, permissions: list, trackers: list, app_category: str = "mobile") -> dict:
    """
    Runs the full AI analysis pipeline for a given app.
    Called by /analyze/ai/{app_id} in main.py

    Args:
        app_id      : unique identifier of the app
        permissions : list of permission name strings
                      e.g. ["android.permission.CAMERA", "android.permission.READ_CONTACTS"]
        trackers    : list of tracker name strings
                      e.g. ["Google Ads", "Facebook SDK"]
        app_category: type of app e.g. "mobile", "health", "ecommerce"

    Returns:
        dict in the exact format the frontend expects:
        {
            "category": "Mobile Application",
            "findings": [...],
            "categories": [...],
            "ai_details": {...}   <- bonus: full AI analysis
        }
    """

    # ── Step 1: Clean permission names ────────────────────────────────────
    # Android permissions come with full package prefix
    # e.g. "android.permission.CAMERA" → we extract just "CAMERA"
    # This makes them cleaner for the AI to analyze
    cleaned_permissions = []
    for p in permissions:
        if "." in p:
            cleaned_permissions.append(p.split(".")[-1])
        else:
            cleaned_permissions.append(p)

    # ── Step 2: Run AI classification ────────────────────────────────────
    # Send each permission to Llama for classification
    print(f"[ai_classifier] classifying {len(cleaned_permissions)} permissions...")
    classifications = classify_multiple_permissions(cleaned_permissions, app_category)

    # ── Step 3: Calculate privacy score ──────────────────────────────────
    print(f"[ai_classifier] calculating privacy score...")
    score_result = calculate_score(classifications, trackers, app_category)

    # ── Step 4: Generate compliance checklist ────────────────────────────
    print(f"[ai_classifier] generating compliance checklist...")
    checklist_result = generate_checklist(app_category, cleaned_permissions, trackers)

    # ── Step 5: Build findings list ───────────────────────────────────────
    # The frontend expects a list of findings with kind, title, desc
    # We generate these from our AI classification results
    findings = []

    # Find excessive permissions
    excessive = [c for c in classifications if c.get("classification") == "EXCESSIVE"]
    necessary = [c for c in classifications if c.get("classification") == "NECESSARY"]
    critical  = [c for c in classifications if c.get("risk_level") == "CRITICAL"]

    if excessive:
        names = ", ".join(c["permission"] for c in excessive[:3])
        findings.append({
            "kind": "issue",
            "title": f"{len(excessive)} excessive permission(s) detected",
            "desc": f"{names} are not justified for this app category and violate GDPR Article 5(1)(c) data minimisation principle."
        })

    if critical:
        findings.append({
            "kind": "issue",
            "title": f"{len(critical)} critical risk permission(s) found",
            "desc": f"Permissions classified as CRITICAL risk can enable surveillance, identity theft, or serious privacy violations if misused."
        })

    if necessary:
        findings.append({
            "kind": "positive",
            "title": f"{len(necessary)} permission(s) are properly justified",
            "desc": f"These permissions match the app's stated purpose and follow the principle of data minimisation."
        })

    # Add tracker-based findings
    if trackers:
        ad_trackers = [t for t in trackers if "ad" in t.lower() or "ads" in t.lower()]
        if ad_trackers:
            findings.append({
                "kind": "issue",
                "title": "Advertising trackers require explicit consent",
                "desc": "GDPR Article 6 requires explicit user consent before advertising SDK initialisation. Consent must be freely given, specific, and informed."
            })

    # Add checklist-based findings
    checklist_items = checklist_result.get("checklist", [])
    failed_items    = [i for i in checklist_items if i.get("status") == "FAIL"]
    if failed_items:
        findings.append({
            "kind": "issue",
            "title": f"{len(failed_items)} compliance check(s) failed",
            "desc": f"The app fails {len(failed_items)} compliance requirements under {checklist_result.get('compliance_framework', 'GDPR')}."
        })

    # ── Step 6: Build data categories ────────────────────────────────────
    # The frontend expects categories with cat, risk, amount, desc
    # We derive these from our classification results
    categories = []

    gdpr_flagged = [c for c in classifications if c.get("gdpr_concern")]
    if gdpr_flagged:
        categories.append({
            "cat": "Personal Identifiers",
            "risk": "high" if len(gdpr_flagged) > 2 else "med",
            "amount": min(0.95, len(gdpr_flagged) * 0.15),
            "desc": "Permissions with GDPR concern flags may expose personal identifiers to third parties."
        })

    if any(c["permission"] in ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"] for c in classifications):
        categories.append({
            "cat": "Location Data",
            "risk": "high",
            "amount": 0.80,
            "desc": "Precise or coarse location data collected. High risk if shared with advertising networks."
        })

    if trackers:
        categories.append({
            "cat": "Behavioral Data",
            "risk": "med",
            "amount": 0.60,
            "desc": "Third-party SDKs may collect usage patterns, session duration, and click stream data."
        })

    if not categories:
        categories.append({
            "cat": "Minimal Data Collection",
            "risk": "low",
            "amount": 0.10,
            "desc": "No significant personal data categories detected based on permission and tracker analysis."
        })

    # ── Step 7: Return final result ───────────────────────────────────────
    return {
        "category": "Mobile Application",
        "findings": findings,
        "categories": categories,
        "ai_details": {
            "privacy_score": score_result.get("score"),
            "grade": score_result.get("grade"),
            "summary": score_result.get("summary"),
            "biggest_risk": score_result.get("biggest_risk"),
            "classifications": classifications,
            "compliance": checklist_result.get("overall_compliance"),
            "checklist": checklist_items
        }
    }