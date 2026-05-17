# classifier.py
# Uses Groq API to run Llama 3.3 70B for permission classification
# Part of the Privacy Posture Analyzer — Member 4 AI Engine

import os
import json
from groq import Groq
from dotenv import load_dotenv
from prompt_engine import get_permission_classification_prompt

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

MODEL = "llama-3.3-70b-versatile"


def classify_permission(permission: str, app_category: str) -> dict:
    """
    Classifies a single permission using Llama 3.3 via Groq.

    Args:
        permission: Android/iOS permission name e.g. READ_CONTACTS
        app_category: type of app e.g. flashlight, health, ecommerce

    Returns:
        dict with keys: permission, classification, risk_level,
        reasoning, gdpr_concern
    """
    try:
        prompt = get_permission_classification_prompt(permission, app_category)

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a privacy engineering expert. Always respond with valid JSON only. No explanation, no markdown, just raw JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=500,
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
            "permission": permission,
            "classification": "UNKNOWN",
            "risk_level": "MEDIUM",
            "reasoning": "Could not parse AI response",
            "gdpr_concern": False
        }
    except Exception as e:
        return {
            "permission": permission,
            "classification": "ERROR",
            "risk_level": "UNKNOWN",
            "reasoning": str(e),
            "gdpr_concern": False
        }


def classify_multiple_permissions(permissions: list, app_category: str) -> list:
    """
    Classifies a list of permissions one by one.
    Focused per-call prompting gives more accurate results
    than sending all permissions in a single request.
    """
    results = []
    for permission in permissions:
        print(f"  classifying: {permission}...")
        result = classify_permission(permission, app_category)
        results.append(result)
    return results


if __name__ == "__main__":
    print("Permission Classifier — Groq/Llama 3.3\n")

    test_permissions = [
        "READ_CONTACTS",
        "CAMERA",
        "ACCESS_FINE_LOCATION",
        "RECORD_AUDIO",
        "READ_CALL_LOG"
    ]

    results = classify_multiple_permissions(test_permissions, "flashlight")

    print("\n" + "-" * 50)
    print("CLASSIFICATION RESULTS")
    print("-" * 50)

    for r in results:
        status = f"[{r['classification']}]".ljust(12)
        risk = f"[{r['risk_level']}]".ljust(10)
        print(f"\n{status} {risk} {r['permission']}")
        print(f"  Reasoning    : {r['reasoning']}")
        print(f"  GDPR Concern : {r['gdpr_concern']}")