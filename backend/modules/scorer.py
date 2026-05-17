# scorer.py
# Calculates the overall privacy posture score (0-100)
# 0 = extremely invasive, 100 = perfectly privacy-respecting
#
# The score uses a weighted penalty system:
# We start at 100 and subtract points based on findings.
# Each category has a maximum penalty it can contribute.

import os
import json
from groq import Groq
from dotenv import load_dotenv
from prompt_engine import get_privacy_score_prompt

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "llama-3.3-70b-versatile"


# ─── Weight table ─────────────────────────────────────────────────────────
# These weights define how much each factor affects the final score.
# They are based on GDPR risk assessment principles.
# Total maximum penalty = 100 points (score bottoms out at 0)

WEIGHTS = {
    "dangerous_permissions": 25,   # permissions like RECORD_AUDIO, READ_CALL_LOG
    "advertising_sdks":      20,   # ad SDKs = profiling risk
    "analytics_trackers":    15,   # behavioral tracking
    "permission_mismatch":   20,   # permissions that don't match app purpose
    "data_minimisation":     20,   # is the app collecting more than it needs
}


def calculate_score(classifications: list, trackers: list, app_category: str) -> dict:
    """
    Calculates the privacy score using two methods combined:
    1. Rule-based: fast local calculation using classification results
    2. AI-based: sends data to Llama for deeper contextual analysis

    Args:
        classifications: list of dicts from classifier.py
        trackers: list of tracker/SDK names e.g. ["Google Ads", "Facebook SDK"]
        app_category: type of app e.g. "flashlight", "health"

    Returns:
        dict with score, grade, summary, biggest_risk, factors
    """

    # Step 1: Rule-based pre-scoring
    # This gives us a fast local score before calling the AI
    local_score = rule_based_score(classifications, trackers)

    # Step 2: AI-based scoring for deeper context
    permissions_list = [c["permission"] for c in classifications]
    ai_score = ai_based_score(permissions_list, trackers, app_category)

    # Step 3: Combine both scores
    # We average them — rule-based ensures consistency,
    # AI-based adds contextual intelligence
    if ai_score:
        final_score = round((local_score["score"] + ai_score["score"]) / 2)
        ai_score["score"] = final_score
        ai_score["grade"] = score_to_grade(final_score)
        ai_score["local_breakdown"] = local_score["breakdown"]
        return ai_score
    else:
        # Fallback to rule-based if AI call fails
        return local_score


def rule_based_score(classifications: list, trackers: list) -> dict:
    """
    Fast local scoring based on classification results.
    No API call needed — uses the results from classifier.py directly.

    Penalty system:
    - Each EXCESSIVE permission with HIGH risk   = -8 points
    - Each EXCESSIVE permission with CRITICAL    = -12 points
    - Each OPTIONAL permission                   = -2 points
    - Each tracker found                         = -5 points
    - Each GDPR concern flagged                  = -3 points
    """
    score = 100
    breakdown = {}

    # Count classification types
    excessive = [c for c in classifications if c["classification"] == "EXCESSIVE"]
    optional  = [c for c in classifications if c["classification"] == "OPTIONAL"]
    gdpr_flags = [c for c in classifications if c.get("gdpr_concern") == True]

    # Apply penalties for excessive permissions
    for c in excessive:
        if c["risk_level"] == "CRITICAL":
            score -= 12
        elif c["risk_level"] == "HIGH":
            score -= 8
        elif c["risk_level"] == "MEDIUM":
            score -= 5
        else:
            score -= 3

    # Apply penalties for optional permissions
    score -= len(optional) * 2

    # Apply penalties for trackers
    score -= len(trackers) * 5

    # Apply penalties for GDPR concerns
    score -= len(gdpr_flags) * 3

    # Score cannot go below 0
    score = max(0, score)

    breakdown["excessive_count"]  = len(excessive)
    breakdown["optional_count"]   = len(optional)
    breakdown["tracker_count"]    = len(trackers)
    breakdown["gdpr_flags"]       = len(gdpr_flags)

    return {
        "score": score,
        "grade": score_to_grade(score),
        "breakdown": breakdown
    }


def ai_based_score(permissions: list, trackers: list, app_category: str) -> dict:
    """
    Sends all findings to Llama for a contextual privacy score.
    The AI considers combinations of permissions that are more
    dangerous together than individually.
    """
    try:
        prompt = get_privacy_score_prompt(permissions, trackers, app_category)

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a privacy auditor. Respond with valid JSON only. No markdown, no explanation."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=600,
        )

        raw_text = response.choices[0].message.content.strip()

        if "```json" in raw_text:
            raw_text = raw_text.split("```json")[1].split("```")[0].strip()
        elif "```" in raw_text:
            raw_text = raw_text.split("```")[1].split("```")[0].strip()

        return json.loads(raw_text)

    except Exception:
        return None


def score_to_grade(score: int) -> str:
    """
    Converts numeric score to a letter grade.

    A = 80-100 : good privacy practices
    B = 60-79  : acceptable with some concerns
    C = 40-59  : significant privacy issues
    D = 20-39  : serious privacy violations
    F = 0-19   : extremely invasive app
    """
    if score >= 80:
        return "A"
    elif score >= 60:
        return "B"
    elif score >= 40:
        return "C"
    elif score >= 20:
        return "D"
    else:
        return "F"


def print_score_report(result: dict):
    """
    Prints a clean formatted score report to the terminal.
    """
    print("-" * 50)
    print("PRIVACY POSTURE SCORE REPORT")
    print("-" * 50)
    print(f"Score        : {result['score']} / 100")
    print(f"Grade        : {result['grade']}")
    print(f"Summary      : {result.get('summary', 'N/A')}")
    print(f"Biggest Risk : {result.get('biggest_risk', 'N/A')}")

    if "local_breakdown" in result:
        print("\nLocal Breakdown:")
        for key, val in result["local_breakdown"].items():
            print(f"  {key.ljust(20)} : {val}")

    if "factors" in result:
        print("\nAI Factor Scores:")
        for key, val in result["factors"].items():
            print(f"  {key.ljust(25)} : {val}")
    print("-" * 50)


if __name__ == "__main__":
    # Simulated input from classifier.py
    # In the real project this comes from classify_multiple_permissions()
    sample_classifications = [
        {"permission": "READ_CONTACTS",       "classification": "EXCESSIVE", "risk_level": "HIGH",     "gdpr_concern": True},
        {"permission": "CAMERA",              "classification": "EXCESSIVE", "risk_level": "HIGH",     "gdpr_concern": True},
        {"permission": "ACCESS_FINE_LOCATION","classification": "EXCESSIVE", "risk_level": "HIGH",     "gdpr_concern": True},
        {"permission": "RECORD_AUDIO",        "classification": "EXCESSIVE", "risk_level": "CRITICAL", "gdpr_concern": True},
        {"permission": "READ_CALL_LOG",       "classification": "EXCESSIVE", "risk_level": "CRITICAL", "gdpr_concern": True},
    ]

    sample_trackers = ["Google Ads", "Facebook SDK", "Crashlytics"]

    print("Calculating privacy score...\n")
    result = calculate_score(sample_classifications, sample_trackers, "flashlight")
    print_score_report(result)