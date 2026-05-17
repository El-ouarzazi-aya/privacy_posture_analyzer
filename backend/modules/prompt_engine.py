# prompt_engine.py
# This file contains all the prompts we send to Gemini
# We separate prompts from logic so they're easy to update

# ─── What is a "prompt"? ───────────────────────────────────────────────
# A prompt is the instruction we give to the AI.
# We use "few-shot prompting" = we give examples inside the prompt
# so Gemini understands exactly what format we want back.
# We also use "chain-of-thought" = we ask Gemini to reason step by step
# before giving its final answer — this improves accuracy.
# ────────────────────────────────────────────────────────────────────────


def get_permission_classification_prompt(permission: str, app_category: str) -> str:
    """
    Builds the prompt to classify a single permission.
    
    Args:
        permission: e.g. "READ_CONTACTS"
        app_category: e.g. "flashlight", "health", "ecommerce"
    
    Returns:
        A full prompt string ready to send to Gemini
    """
    return f"""
You are a privacy engineering expert specialized in mobile app auditing.
Your job is to classify Android/iOS permissions based on their necessity for a given app type.

classify this permission for a {app_category} app:
Permission: {permission}

Think step by step:
1. What does this permission allow the app to access?
2. Is this access logically needed for a {app_category} app?
3. Could the app work without it?
4. What is the privacy risk if misused?

Then respond ONLY with this exact JSON format, nothing else:
{{
  "permission": "{permission}",
  "classification": "NECESSARY" | "OPTIONAL" | "EXCESSIVE",
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "reasoning": "one sentence explanation",
  "gdpr_concern": true | false
}}

Examples:
- CAMERA for a QR scanner app → NECESSARY, LOW risk
- READ_CONTACTS for a flashlight app → EXCESSIVE, HIGH risk
- LOCATION for a food delivery app → NECESSARY, MEDIUM risk
- READ_CALL_LOG for a calculator app → EXCESSIVE, CRITICAL risk
"""


def get_privacy_score_prompt(permissions: list, trackers: list, app_category: str) -> str:
    """
    Builds the prompt to calculate the overall privacy score (0-100).
    """
    return f"""
You are a privacy auditor. Score this {app_category} app's privacy posture from 0 to 100.
0 = extremely invasive, 100 = perfectly privacy-respecting.

App data:
- Permissions requested: {permissions}
- Third-party trackers embedded: {trackers}
- App category: {app_category}

Scoring rules:
- Start at 100
- Subtract points for each issue found
- dangerous_permissions: subtract 0-25 based on how many dangerous permissions exist
- advertising_sdks: subtract 0-20 based on ad SDK presence
- analytics_trackers: subtract 0-15 based on analytics tracker presence
- permission_mismatch: subtract 0-20 based on how many permissions don't match app purpose
- data_minimisation: subtract 0-20 based on how much unnecessary data is collected

Each factor value in your response must be the POINTS DEDUCTED (not points earned).
For example if the app has many dangerous permissions, dangerous_permissions should be close to 25.
The final score = 100 minus the sum of all factor deductions.

Respond ONLY with this exact JSON, no explanation:
{{
  "score": <final number 0-100>,
  "grade": "A" | "B" | "C" | "D" | "F",
  "summary": "one sentence overall assessment",
  "biggest_risk": "the single most concerning finding",
  "factors": {{
    "dangerous_permissions": <0-25 points deducted>,
    "advertising_sdks": <0-20 points deducted>,
    "analytics_trackers": <0-15 points deducted>,
    "permission_mismatch": <0-20 points deducted>,
    "data_minimisation": <0-20 points deducted>
  }}
}}
"""


def get_checklist_prompt(app_category: str, permissions: list, trackers: list) -> str:
    """
    Builds the prompt to generate a sector-specific privacy checklist.
    
    Args:
        app_category: "health" | "education" | "ecommerce" | "gaming"
        permissions: list of detected permissions
        trackers: list of detected trackers
    
    Returns:
        A full prompt string ready to send to Gemini
    """
    return f"""
You are a GDPR/CCPA compliance expert. Generate a privacy checklist for a {app_category} app.

App context:
- Detected permissions: {permissions}
- Detected trackers: {trackers}

Generate a tailored checklist with exactly this JSON format:
{{
  "app_category": "{app_category}",
  "compliance_framework": "GDPR" | "GDPR+COPPA" | "GDPR+HIPAA" | "GDPR+PCI-DSS",
  "checklist": [
    {{
      "id": 1,
      "check": "description of what to verify",
      "status": "PASS" | "FAIL" | "REVIEW",
      "priority": "HIGH" | "MEDIUM" | "LOW",
      "gdpr_article": "Article X" or null,
      "recommendation": "specific action to take"
    }}
  ],
  "overall_compliance": "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT"
}}

Generate between 8 and 12 checklist items relevant to {app_category} apps.
Focus on the most critical privacy risks for this sector.
"""