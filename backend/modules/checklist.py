# checklist.py
# Generates a sector-specific privacy compliance checklist using Llama 3.3
# Each checklist is tailored to the app category and its specific findings
# Items are mapped to real GDPR articles for legal accuracy

import os
import json
from groq import Groq
from dotenv import load_dotenv
from prompt_engine import get_checklist_prompt

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "llama-3.3-70b-versatile"


# ─── Sector profiles ──────────────────────────────────────────────────────
# Each sector has known high-risk areas and relevant compliance frameworks.
# We use this to enrich the prompt with context before sending to the AI.
# This is called "context injection" — giving the AI domain knowledge
# so it produces more accurate and relevant checklists.

SECTOR_PROFILES = {
    "health": {
        "framework": "GDPR + HIPAA",
        "high_risk": ["health metrics", "medical records", "biometric data"],
        "forbidden": ["advertising SDKs", "behavioral tracking", "data selling"],
    },
    "education": {
        "framework": "GDPR + COPPA",
        "high_risk": ["child data", "behavioral profiling", "location tracking"],
        "forbidden": ["advertising SDKs", "IDFA/GAID collection", "social SDKs"],
    },
    "ecommerce": {
        "framework": "GDPR + PCI-DSS",
        "high_risk": ["payment data", "purchase history", "behavioral profiling"],
        "forbidden": ["sharing purchase history with ad networks"],
    },
    "gaming": {
        "framework": "GDPR",
        "high_risk": ["behavioral profiling", "in-app purchases", "social SDKs"],
        "forbidden": ["cross-app tracking without consent", "no age gate"],
    },
    "flashlight": {
        "framework": "GDPR",
        "high_risk": ["unnecessary permissions", "hidden data collection"],
        "forbidden": ["any permission not related to torch functionality"],
    },
}


def generate_checklist(app_category: str, permissions: list, trackers: list) -> dict:
    """
    Generates a compliance checklist for the given app.

    Args:
        app_category: sector of the app e.g. health, education, ecommerce, gaming
        permissions: list of permission names found in the app
        trackers: list of tracker/SDK names found in the app

    Returns:
        dict with checklist items, compliance status, and framework

    How it works:
    1. We look up the sector profile for extra context
    2. We build an enriched prompt combining findings + sector knowledge
    3. We send it to Llama which generates relevant checklist items
    4. We parse and return the structured result
    """

    # Step 1: Get sector profile or use a generic one
    profile = SECTOR_PROFILES.get(app_category, {
        "framework": "GDPR",
        "high_risk": ["unnecessary data collection"],
        "forbidden": ["excessive permissions"],
    })

    # Step 2: Build the prompt using our prompt engine
    base_prompt = get_checklist_prompt(app_category, permissions, trackers)

    # Step 3: Inject sector context into the prompt
    # This makes the AI aware of sector-specific rules
    enriched_prompt = f"""
{base_prompt}

Additional sector context for {app_category}:
- Compliance framework: {profile['framework']}
- Known high-risk areas for this sector: {profile['high_risk']}
- Practices that are forbidden in this sector: {profile['forbidden']}

Make sure your checklist addresses these sector-specific concerns directly.
"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a GDPR and privacy compliance expert. Respond with valid JSON only. No markdown, no explanation."
                },
                {
                    "role": "user",
                    "content": enriched_prompt
                }
            ],
            temperature=0.2,
            max_tokens=1500,  # Checklist is longer so we allow more tokens
        )

        raw_text = response.choices[0].message.content.strip()

        if "```json" in raw_text:
            raw_text = raw_text.split("```json")[1].split("```")[0].strip()
        elif "```" in raw_text:
            raw_text = raw_text.split("```")[1].split("```")[0].strip()

        result = json.loads(raw_text)
        return result

    except json.JSONDecodeError:
        return {
            "app_category": app_category,
            "compliance_framework": profile["framework"],
            "checklist": [],
            "overall_compliance": "ERROR",
            "error": "Could not parse AI response"
        }
    except Exception as e:
        return {
            "app_category": app_category,
            "compliance_framework": profile["framework"],
            "checklist": [],
            "overall_compliance": "ERROR",
            "error": str(e)
        }


def print_checklist_report(result: dict):
    """
    Prints a clean formatted checklist to the terminal.

    Status indicators:
    [PASS]   - app is doing this correctly
    [FAIL]   - app is violating this requirement
    [REVIEW] - needs manual human review
    """
    print("-" * 60)
    print("PRIVACY COMPLIANCE CHECKLIST")
    print("-" * 60)
    print(f"App Category  : {result.get('app_category', 'N/A').upper()}")
    print(f"Framework     : {result.get('compliance_framework', 'N/A')}")
    print(f"Compliance    : {result.get('overall_compliance', 'N/A')}")
    print("-" * 60)

    checklist = result.get("checklist", [])

    if not checklist:
        print("No checklist items generated.")
        return

    # Group items by priority for cleaner output
    high    = [i for i in checklist if i.get("priority") == "HIGH"]
    medium  = [i for i in checklist if i.get("priority") == "MEDIUM"]
    low     = [i for i in checklist if i.get("priority") == "LOW"]

    for group_name, group in [("HIGH PRIORITY", high), ("MEDIUM PRIORITY", medium), ("LOW PRIORITY", low)]:
        if group:
            print(f"\n{group_name}")
            print("-" * 40)
            for item in group:
                status  = f"[{item.get('status', '?')}]".ljust(8)
                gdpr    = f"({item.get('gdpr_article', '')})" if item.get('gdpr_article') else ""
                print(f"{status} {item.get('check', '')} {gdpr}")
                print(f"         Recommendation: {item.get('recommendation', '')}")

    # Summary counts
    passed  = len([i for i in checklist if i.get("status") == "PASS"])
    failed  = len([i for i in checklist if i.get("status") == "FAIL"])
    review  = len([i for i in checklist if i.get("status") == "REVIEW"])

    print("\n" + "-" * 60)
    print(f"Results  ->  PASS: {passed}  |  FAIL: {failed}  |  REVIEW: {review}")
    print("-" * 60)


if __name__ == "__main__":
    # ── Illustrative example: FitTracker Pro (health/fitness app) ─────────
    # Expected OWASP risks: M2, M5, M6, M9
    # Expected GDPR framework: GDPR + HIPAA
    # Excessive permissions flag M6 (Privacy Controls) and M9 (Data Storage)
    sample_permissions = [
        "ACCESS_FINE_LOCATION",
        "RECORD_AUDIO",
        "READ_CONTACTS",
        "READ_CALL_LOG",
        "CAMERA",
        "READ_EXTERNAL_STORAGE",
        "INTERNET",
        "POST_NOTIFICATIONS",
        "BLUETOOTH_SCAN",
        "READ_PHONE_STATE",
    ]

    sample_trackers = ["Google Ads", "Facebook SDK", "AppsFlyer", "Crashlytics"]

    print("Generating compliance checklist — FitTracker Pro (health)\n")
    print("OWASP Mobile Top 10 alignment: M2, M5, M6, M9\n")

    result = generate_checklist("health", sample_permissions, sample_trackers)
    print_checklist_report(result)