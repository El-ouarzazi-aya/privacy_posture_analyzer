"""
main.py — Privacy Posture Analyzer
Full backend: upload + all endpoints the frontend calls
"""
import io as _io
import os
import re
from datetime import date

from typing import List

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import engine, SessionLocal
from models import Base, Audit, Tracker
from modules.ai_classifier import run_ai_analysis
from modules.trackers import router as trackers_router
from modules.permissions import analyze_permissions as _parse_permissions, get_owasp_assessment
from modules.report import build_pdf

Base.metadata.create_all(bind=engine)
os.makedirs("uploads", exist_ok=True)

app = FastAPI(title="Privacy Posture Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(trackers_router)


# ── Serve the frontend HTML ────────────────────────────────────────────────
@app.get("/app")
def serve_frontend():
    html_path = os.path.join(os.path.dirname(__file__), "..", "Privacy_Posture_Analyzer.html")
    return FileResponse(os.path.abspath(html_path))


def get_db():
    return SessionLocal()


def _risk_label(score):
    if score >= 70:
        return "high"
    if score >= 45:
        return "med"
    return "low"


@app.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted.")
    raw_name = os.path.splitext(file.filename)[0]
    app_id = re.sub(r'[^A-Za-z0-9_\-]', '_', raw_name)
    apk_path = os.path.join("uploads", f"{app_id}.apk")
    contents = await file.read()
    with open(apk_path, "wb") as f:
        f.write(contents)
    apk_size_mb = round(len(contents) / (1024 * 1024), 3)
    db = get_db()
    try:
        existing = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not existing:
            audit = Audit(
                app_id=app_id,
                app_name=os.path.splitext(file.filename)[0],
                package_name=app_id,
                apk_size_mb=apk_size_mb,
                privacy_score=None,
            )
            db.add(audit)
            db.commit()
            db.refresh(audit)
    finally:
        db.close()
    return {
        "app_id": app_id,
        "app_name": file.filename,
        "package": app_id,
        "apk_size_mb": apk_size_mb,
        "message": "APK uploaded successfully.",
    }


@app.post("/analyze/permissions/{app_id}")
def analyze_permissions(app_id: str):
    db = get_db()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found.")
    finally:
        db.close()

    try:
        return _parse_permissions(app_id)
    except FileNotFoundError:
        return {
            "permissions": [
                {"name": "android.permission.INTERNET",
                 "risk": "low", "label": "Necessary"},
            ],
            "breakdown": {"necessary": 1, "optional": 0, "excessive": 0},
        }


@app.post("/analyze/ai/{app_id}")
def analyze_ai(app_id: str):
    """
    Runs the real AI analysis using the Groq/Llama engine.
    Owned by Member 4 — AI Engine module.
    """
    db = get_db()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found.")
        trackers = db.query(Tracker).filter(Tracker.audit_id == audit.id).all()
    finally:
        db.close()

    tracker_names = [t.sdk_name for t in trackers]

    permissions = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ]

    app_category = "mobile"
    if any("health" in t.sdk_name.lower() for t in trackers):
        app_category = "health"
    elif any("game" in t.sdk_name.lower() for t in trackers):
        app_category = "gaming"

    result = run_ai_analysis(
        app_id=app_id,
        permissions=permissions,
        trackers=tracker_names,
        app_category=app_category,
    )
    return result


@app.get("/report/{app_id}")
def get_report(app_id: str):
    db = get_db()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found.")
        trackers = db.query(Tracker).filter(Tracker.audit_id == audit.id).all()
    finally:
        db.close()

    sdk_scores = [t.risk_score for t in trackers] if trackers else [0]
    avg_sdk = int(sum(sdk_scores) / len(sdk_scores))
    sdk_privacy = max(0, 100 - avg_sdk)
    perm_score = 80
    gdpr_score = max(0, sdk_privacy - 5)
    overall = int((sdk_privacy * 0.5) + (perm_score * 0.3) + (gdpr_score * 0.2))

    db2 = get_db()
    try:
        a = db2.query(Audit).filter(Audit.app_id == app_id).first()
        if a:
            a.privacy_score = overall
            db2.commit()
    finally:
        db2.close()

    ai = analyze_ai(app_id)
    perms = analyze_permissions(app_id)

    # OWASP Mobile Top 10 assessment
    perm_names = [p["name"] for p in perms["permissions"]]
    tracker_names = [t.sdk_name for t in trackers]
    owasp = get_owasp_assessment(perm_names, tracker_names)

    return {
        "app_id": app_id,
        "name": audit.app_name or app_id,
        "pkg": audit.package_name or app_id,
        "version": "—",
        "sdkVersion": "Android",
        "size": f"{audit.apk_size_mb} MB" if audit.apk_size_mb else "—",
        "category": "Mobile Application",
        "score": overall,
        "sdks": [
            {
                "name": t.sdk_name,
                "version": "—",
                "risk": _risk_label(t.risk_score),
                "score": t.risk_score,
            }
            for t in trackers
        ],
        "permissions": perms["permissions"],
        "breakdown": {
            "permissions": perm_score,
            "sdks": sdk_privacy,
            "gdpr": gdpr_score,
            "necessary": perms["breakdown"]["necessary"],
            "optional": perms["breakdown"]["optional"],
            "excessive": perms["breakdown"]["excessive"],
        },
        "categories": ai["categories"],
        "findings": ai["findings"],
        "owasp": owasp,
    }


@app.get("/report/{app_id}/pdf")
def download_pdf_report(app_id: str):
    report = get_report(app_id)
    pdf_bytes = build_pdf(report)
    return StreamingResponse(
        _io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{app_id}_privacy_report.pdf"'},
    )


@app.get("/report/{app_id}/ai-details")
def get_ai_details(app_id: str):
    """
    Returns the full AI analysis for a given app.
    Owned by Member 4 — exposes complete classification,
    checklist, and score details to the frontend.
    """
    db = get_db()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found.")
        trackers = db.query(Tracker).filter(Tracker.audit_id == audit.id).all()
    finally:
        db.close()

    tracker_names = [t.sdk_name for t in trackers]
    permissions = getattr(audit, "permissions", None) or [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ]
    app_category = "mobile"

    result = run_ai_analysis(
        app_id=app_id,
        permissions=permissions,
        trackers=tracker_names,
        app_category=app_category,
    )
    return {
        "app_id": app_id,
        "app_name": audit.app_name,
        "ai_analysis": result,
    }


@app.get("/history")
def get_history():
    db = get_db()
    try:
        audits = db.query(Audit).order_by(Audit.created_at.desc()).all()
    finally:
        db.close()
    return {
        "audits": [
            {
                "app_id": a.app_id,
                "app_name": a.app_name or a.app_id,
                "package": a.package_name or a.app_id,
                "score": a.privacy_score if a.privacy_score is not None else 0,
                "date": str(a.created_at)[:10] if a.created_at else str(date.today()),
            }
            for a in audits
        ]
    }


@app.delete("/audit/{app_id}")
def delete_audit(app_id: str):
    db = get_db()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found.")
        db.query(Tracker).filter(Tracker.audit_id == audit.id).delete()
        db.delete(audit)
        db.commit()
        apk_path = os.path.join("uploads", f"{app_id}.apk")
        if os.path.exists(apk_path):
            os.remove(apk_path)
    finally:
        db.close()
    return {"ok": True}


@app.get("/owasp/{app_id}")
def get_owasp_report(app_id: str):
    """Return the OWASP Mobile Top 10 assessment for a given app."""
    db = get_db()
    try:
        audit = db.query(Audit).filter(Audit.app_id == app_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found.")
        trackers = db.query(Tracker).filter(Tracker.audit_id == audit.id).all()
    finally:
        db.close()

    try:
        perms = _parse_permissions(app_id)
    except FileNotFoundError:
        perms = {"permissions": [], "breakdown": {}}

    perm_names = [p["name"] for p in perms["permissions"]]
    tracker_names = [t.sdk_name for t in trackers]
    owasp = get_owasp_assessment(perm_names, tracker_names)
    return {"app_id": app_id, "app_name": audit.app_name, **owasp}


class CompareRequest(BaseModel):
    app_ids: List[str]


@app.post("/compare")
def compare_apps(body: CompareRequest):
    """
    Side-by-side comparison of multiple APKs.
    Returns a list of summarised reports for each app_id.
    """
    results = []
    for app_id in body.app_ids[:5]:  # cap at 5 apps
        try:
            report = get_report(app_id)
            results.append({
                "app_id":      app_id,
                "name":        report["name"],
                "score":       report["score"],
                "owasp_risks": report.get("owasp", {}).get("risk_count", 0),
                "excessive":   report["breakdown"]["excessive"],
                "sdk_count":   len(report["sdks"]),
                "top_risks":   report.get("owasp", {}).get("top_risks", []),
                "findings":    report["findings"],
                "owasp":       report.get("owasp", {}),
            })
        except HTTPException as exc:
            results.append({"app_id": app_id, "error": exc.detail})
        except Exception as exc:
            results.append({"app_id": app_id, "error": str(exc)})
    return {"comparisons": results, "count": len(results)}


@app.get("/")
def root():
    return {"status": "Privacy Posture Analyzer is running"}
