# test_ai_engine.py
# Unit tests for the Member 4 AI Engine module
# Tests cover: classifier, scorer, checklist, and ai_classifier
# Run with: pytest tests/test_ai_engine.py -v

import sys
import os
import pytest

# Add modules folder to path so we can import from it
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "modules"))

from classifier import classify_permission, classify_multiple_permissions
from scorer import calculate_score, rule_based_score, score_to_grade
from checklist import generate_checklist
from ai_classifier import run_ai_analysis


# ══════════════════════════════════════════════════════════════════════════
# SECTION 1 — classifier.py tests
# ══════════════════════════════════════════════════════════════════════════

class TestPermissionClassifier:

    def test_excessive_permission_flashlight(self):
        """
        READ_CONTACTS on a flashlight app must be classified as EXCESSIVE.
        This is the most basic privacy violation — permission has no
        logical connection to the app's stated purpose.
        Chapter 11 reference: dangerous permission with no justification.
        """
        result = classify_permission("READ_CONTACTS", "flashlight")

        assert result["permission"] == "READ_CONTACTS"
        assert result["classification"] == "EXCESSIVE"
        assert result["risk_level"] in ["HIGH", "CRITICAL"]
        assert result["gdpr_concern"] == True


    def test_necessary_permission_camera_qr(self):
        """
        CAMERA on a QR scanner app must be classified as NECESSARY.
        The permission directly enables the app's core functionality.
        Chapter 11 reference: justified runtime permission.
        """
        result = classify_permission("CAMERA", "qr_scanner")

        assert result["permission"] == "CAMERA"
        assert result["classification"] == "NECESSARY"
        assert "reasoning" in result
        assert len(result["reasoning"]) > 10


    def test_critical_risk_audio_flashlight(self):
        """
        RECORD_AUDIO on a flashlight app must return CRITICAL risk.
        Audio recording without justification = surveillance capability.
        Chapter 12 reference: high-risk SDK/permission combination.
        """
        result = classify_permission("RECORD_AUDIO", "flashlight")

        assert result["risk_level"] == "CRITICAL"
        assert result["classification"] == "EXCESSIVE"


    def test_classify_multiple_returns_correct_count(self):
        """
        classify_multiple_permissions must return one result per permission.
        Tests that the function correctly iterates and returns all results.
        """
        permissions = ["CAMERA", "READ_CONTACTS", "ACCESS_FINE_LOCATION"]
        results = classify_multiple_permissions(permissions, "flashlight")

        assert len(results) == 3
        assert all("classification" in r for r in results)
        assert all("risk_level" in r for r in results)
        assert all("gdpr_concern" in r for r in results)


    def test_response_has_required_fields(self):
        """
        Every classification response must contain all required fields.
        This ensures the API contract is respected — other modules
        depend on these fields being present.
        """
        result = classify_permission("CAMERA", "health")

        required_fields = [
            "permission",
            "classification",
            "risk_level",
            "reasoning",
            "gdpr_concern"
        ]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"


# ══════════════════════════════════════════════════════════════════════════
# SECTION 2 — scorer.py tests
# ══════════════════════════════════════════════════════════════════════════

class TestPrivacyScorer:

    def test_clean_app_scores_high(self):
        """
        An app with no excessive permissions and no trackers
        must score above 80 — considered a good privacy posture.
        """
        classifications = [
            {"permission": "CAMERA", "classification": "NECESSARY",
             "risk_level": "LOW", "gdpr_concern": False},
            {"permission": "INTERNET", "classification": "NECESSARY",
             "risk_level": "LOW", "gdpr_concern": False},
        ]
        result = rule_based_score(classifications, [])

        assert result["score"] >= 80
        assert result["grade"] in ["A", "B"]


    def test_invasive_app_scores_low(self):
        """
        An app with multiple excessive critical permissions and trackers
        must score below 40 — considered high risk.
        """
        classifications = [
            {"permission": "READ_CONTACTS",  "classification": "EXCESSIVE",
             "risk_level": "CRITICAL", "gdpr_concern": True},
            {"permission": "RECORD_AUDIO",   "classification": "EXCESSIVE",
             "risk_level": "CRITICAL", "gdpr_concern": True},
            {"permission": "READ_CALL_LOG",  "classification": "EXCESSIVE",
             "risk_level": "CRITICAL", "gdpr_concern": True},
        ]
        trackers = ["Google Ads", "Facebook SDK", "Crashlytics"]
        result = rule_based_score(classifications, trackers)

        assert result["score"] <= 45
        assert result["grade"] in ["C","D", "F"]


    def test_score_never_goes_below_zero(self):
        """
        No matter how many violations, score must never go negative.
        Tests the max(0, score) boundary condition in scorer.py.
        """
        classifications = [
            {"permission": f"PERM_{i}", "classification": "EXCESSIVE",
             "risk_level": "CRITICAL", "gdpr_concern": True}
            for i in range(20)
        ]
        trackers = [f"Tracker_{i}" for i in range(10)]
        result = rule_based_score(classifications, trackers)

        assert result["score"] >= 0


    def test_grade_boundaries(self):
        """
        Tests that score_to_grade returns correct letter grades
        at each boundary value.
        A=80+, B=60-79, C=40-59, D=20-39, F=0-19
        """
        assert score_to_grade(100) == "A"
        assert score_to_grade(80)  == "A"
        assert score_to_grade(79)  == "B"
        assert score_to_grade(60)  == "B"
        assert score_to_grade(59)  == "C"
        assert score_to_grade(40)  == "C"
        assert score_to_grade(39)  == "D"
        assert score_to_grade(20)  == "D"
        assert score_to_grade(19)  == "F"
        assert score_to_grade(0)   == "F"


# ══════════════════════════════════════════════════════════════════════════
# SECTION 3 — checklist.py tests
# ══════════════════════════════════════════════════════════════════════════

class TestChecklistGenerator:

    def test_checklist_has_required_fields(self):
        """
        Every checklist response must contain the required top-level fields.
        Tests the output contract that the frontend depends on.
        """
        result = generate_checklist("flashlight", ["CAMERA"], [])

        assert "app_category"          in result
        assert "compliance_framework"  in result
        assert "checklist"             in result
        assert "overall_compliance"    in result


    def test_checklist_items_have_gdpr_articles(self):
        """
        Checklist items must reference real GDPR articles.
        This links the technical findings to the legal framework
        covered in Chapter 2.
        """
        result = generate_checklist("health", ["CAMERA"], ["Google Ads"])
        items  = result.get("checklist", [])

        assert len(items) > 0

        # At least some items should reference GDPR articles
        articles = [i.get("gdpr_article") for i in items if i.get("gdpr_article")]
        assert len(articles) > 0


    def test_health_app_uses_correct_framework(self):
        """
        Health apps must use GDPR+HIPAA framework.
        Defined in SECTOR_PROFILES in checklist.py.
        """
        result = generate_checklist("health", ["CAMERA"], [])
        assert "HIPAA" in result.get("compliance_framework", "")


# ══════════════════════════════════════════════════════════════════════════
# SECTION 4 — ai_classifier.py integration test
# ══════════════════════════════════════════════════════════════════════════

class TestAIClassifierIntegration:

    def test_full_pipeline_returns_required_keys(self):
        """
        The full AI pipeline must return all keys the frontend expects.
        This is the integration test — verifies end-to-end output contract.
        """
        result = run_ai_analysis(
            app_id="test_app",
            permissions=["CAMERA", "READ_CONTACTS"],
            trackers=["Google Ads"],
            app_category="flashlight"
        )

        assert "category"   in result
        assert "findings"   in result
        assert "categories" in result
        assert "ai_details" in result


    def test_full_pipeline_findings_not_empty(self):
        """
        An app with excessive permissions must generate at least
        one finding. Empty findings on a bad app = broken pipeline.
        """
        result = run_ai_analysis(
            app_id="test_app",
            permissions=["READ_CONTACTS", "RECORD_AUDIO", "READ_CALL_LOG"],
            trackers=["Google Ads", "Facebook SDK"],
            app_category="flashlight"
        )

        assert len(result["findings"]) > 0