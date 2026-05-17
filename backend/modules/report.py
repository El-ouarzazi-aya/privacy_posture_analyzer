"""
report.py — Member 3: Report Generator
Builds the full PDF privacy audit report and exposes the download endpoint.
"""
import io as _io

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.graphics.shapes import Drawing, Rect, String

# ── Light-mode colour palette ──────────────────────────────────────────────
_BG      = colors.HexColor("#FAFAF8")
_SURFACE = colors.HexColor("#FFFFFF")
_SURFACE2= colors.HexColor("#F4F2EE")
_OLIVE   = colors.HexColor("#4A5E2A")
_STONE   = colors.HexColor("#8A8078")
_TERRA   = colors.HexColor("#B05A38")
_TEXT    = colors.HexColor("#1A1A18")
_MUTED   = colors.HexColor("#6A6A66")
_BORDER  = colors.HexColor("#E5E2DC")


def _risk_color(score: int):
    if score >= 70: return _TERRA
    if score >= 45: return _STONE
    return _OLIVE


def _score_color(score: int):
    if score >= 70: return _OLIVE
    if score >= 40: return _STONE
    return _TERRA


def _style(name, **kw):
    defaults = dict(fontName="Helvetica", fontSize=10,
                    textColor=_TEXT, leading=14, spaceAfter=4)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)


def _dedup_sdks(sdks: list) -> list:
    """Remove duplicate SDKs keeping only the first occurrence."""
    seen = set()
    result = []
    for sdk in sdks:
        key = sdk.get("name", "")
        if key not in seen:
            seen.add(key)
            result.append(sdk)
    return result


def build_pdf(report: dict) -> bytes:
    buf = _io.BytesIO()
    W, H = A4
    M = 18 * mm

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=M, rightMargin=M,
        topMargin=M, bottomMargin=M,
    )

    def _bg_canvas(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.setFillColor(_OLIVE)
        canvas.rect(0, H - 3, W, 3, fill=1, stroke=0)
        canvas.setFillColor(_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(M, 10 * mm, "Privacy Posture Analyzer  —  Confidential Audit Report")
        canvas.drawRightString(W - M, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []
    s = lambda n, **kw: _style(n, **kw)

    # ── HEADER ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        '<font name="Helvetica" size="8" color="#4A5E2A">— PRIVACY AUDIT REPORT</font>',
        s("label", alignment=TA_LEFT),
    ))
    story.append(Spacer(1, 2 * mm))

    app_name = report.get("name", "Unknown App")
    story.append(Paragraph(
        f'<font name="Helvetica-Bold" size="20" color="#1A1A18">{app_name}</font>',
        s("title"),
    ))
    story.append(Paragraph(
        f'<font name="Helvetica" size="10" color="#6A6A66">{report.get("pkg", "")}</font>',
        s("pkg"),
    ))
    story.append(Spacer(1, 3 * mm))

    # ── META ROW ──────────────────────────────────────────────────────────
    meta_items = [
        ("Version",  report.get("version", "—")),
        ("Target",   report.get("sdkVersion", "—")),
        ("Size",     report.get("size", "—")),
        ("Category", report.get("category", "—")),
    ]
    meta_data = [[
        Paragraph(
            f'<font size="7" color="#6A6A66">— {k}</font><br/>'
            f'<font size="10" color="#1A1A18">{v}</font>',
            s(f"m{i}"),
        )
        for i, (k, v) in enumerate(meta_items)
    ]]
    meta_tbl = Table(meta_data, colWidths=[(W - 2 * M) / 4] * 4)
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _SURFACE),
        ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, _BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 5 * mm))

    # ── SCORE BANNER ─────────────────────────────────────────────────────
    # FIX: score on left as plain text, description on right — no overlap
    score = report.get("score", 0)
    sc = _score_color(score)
    score_label = (
        "HIGH PRIVACY" if score >= 70
        else ("MODERATE RISK" if score >= 40 else "HIGH RISK")
    )
    score_data = [[
        Paragraph(
            '<font name="Helvetica" size="8" color="#6A6A66">— PRIVACY SCORE</font><br/>'
            f'<font name="Helvetica-Bold" size="42" color="{sc.hexval()}">{score}</font><br/>'
            '<font name="Helvetica" size="11" color="#6A6A66">/100</font>',
            s("score_num", alignment=TA_CENTER, leading=46),
        ),
        Paragraph(
            f'<font name="Helvetica-Bold" size="13" color="{sc.hexval()}">{score_label}</font><br/><br/>'
            f'<font size="9" color="#6A6A66">This application scored {score}/100 on the Privacy Posture '
            'Analyzer. The score reflects SDK risk exposure, permission usage, and GDPR compliance posture.</font>',
            s("score_desc", leading=16),
        ),
    ]]
    score_tbl = Table(score_data, colWidths=[42 * mm, W - 2 * M - 42 * mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _SURFACE),
        ("BOX",           (0, 0), (-1, -1), 1, _OLIVE),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, _BORDER),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 6 * mm))

    # ── SCORE BREAKDOWN ───────────────────────────────────────────────────
    story.append(Paragraph(
        '<font name="Helvetica-Bold" size="12" color="#1A1A18">01 — Score Breakdown</font>',
        s("h2"),
    ))
    story.append(Spacer(1, 2 * mm))

    bd = report.get("breakdown", {})
    for bar_label, key in [
        ("Permissions", "permissions"),
        ("SDKs", "sdks"),
        ("GDPR Compliance", "gdpr"),
    ]:
        val = bd.get(key, 0)
        label_w = 72 * mm   # fixed label column
        score_w = 20 * mm   # fixed score column
        bar_w   = W - 2 * M - label_w - score_w
        filled  = bar_w * val / 100
        total_w = W - 2 * M
        d = Drawing(total_w, 18)
        # label on the left
        d.add(String(0, 5, bar_label, fontName="Helvetica", fontSize=9, fillColor=_TEXT))
        # bar in the middle
        d.add(Rect(label_w, 6, bar_w, 4, fillColor=_BORDER, strokeColor=None))
        d.add(Rect(label_w, 6, filled, 4, fillColor=_risk_color(100 - val), strokeColor=None))
        # score on the far right — never overlaps bar
        d.add(String(total_w, 5, f"{val}/100",
                     fontName="Helvetica", fontSize=9, fillColor=_MUTED, textAnchor="end"))
        story.append(d)
        story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 5 * mm))

    # ── PERMISSIONS ───────────────────────────────────────────────────────
    perms = report.get("permissions", [])
    if perms:
        story.append(Paragraph(
            '<font name="Helvetica-Bold" size="12" color="#1A1A18">02 — Permissions</font>',
            s("h2"),
        ))
        story.append(Spacer(1, 2 * mm))

        perm_summary = [[
            Paragraph(
                f'<font size="7" color="#6A6A66">— NECESSARY</font><br/>'
                f'<font name="Helvetica-Bold" size="18" color="#4A5E2A">{bd.get("necessary", 0)}</font>',
                s("pbd"),
            ),
            Paragraph(
                f'<font size="7" color="#6A6A66">— OPTIONAL</font><br/>'
                f'<font name="Helvetica-Bold" size="18" color="#8A8078">{bd.get("optional", 0)}</font>',
                s("pbd"),
            ),
            Paragraph(
                f'<font size="7" color="#6A6A66">— EXCESSIVE</font><br/>'
                f'<font name="Helvetica-Bold" size="18" color="#B05A38">{bd.get("excessive", 0)}</font>',
                s("pbd"),
            ),
        ]]
        psum_tbl = Table(perm_summary, colWidths=[(W - 2 * M) / 3] * 3)
        psum_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _SURFACE),
            ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, _BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ]))
        story.append(psum_tbl)
        story.append(Spacer(1, 3 * mm))

        perm_header = [
            Paragraph('<font size="8" color="#6A6A66">PERMISSION</font>', s("th", alignment=TA_LEFT)),
            Paragraph('<font size="8" color="#6A6A66">RISK</font>',       s("th", alignment=TA_CENTER)),
            Paragraph('<font size="8" color="#6A6A66">LABEL</font>',      s("th", alignment=TA_CENTER)),
        ]
        perm_rows = [perm_header]
        for p in perms[:30]:
            risk = p.get("risk", "low")
            rc = _TERRA if risk == "high" else (_STONE if risk == "med" else _OLIVE)
            perm_rows.append([
                Paragraph(f'<font size="8" color="#1A1A18">{p.get("name", "")}</font>', s("td")),
                Paragraph(f'<font name="Helvetica-Bold" size="8" color="{rc.hexval()}">{risk.upper()}</font>',
                          s("td", alignment=TA_CENTER)),
                Paragraph(f'<font size="8" color="#6A6A66">{p.get("label", "")}</font>',
                          s("td", alignment=TA_CENTER)),
            ])
        col_w = W - 2 * M
        perm_tbl = Table(perm_rows, colWidths=[col_w * 0.70, col_w * 0.15, col_w * 0.15])
        perm_tbl.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0),  _SURFACE2),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
            ("BOX",            (0, 0), (-1, -1), 0.5, _BORDER),
            ("INNERGRID",      (0, 0), (-1, -1), 0.3, _BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(perm_tbl)
        story.append(Spacer(1, 6 * mm))

    # ── SDK TABLE (deduplicated) ───────────────────────────────────────────
    sdks = _dedup_sdks(report.get("sdks", []))  # FIX: deduplicate
    if sdks:
        story.append(Paragraph(
            '<font name="Helvetica-Bold" size="12" color="#1A1A18">03 — Embedded SDKs</font>',
            s("h2"),
        ))
        story.append(Spacer(1, 2 * mm))

        sdk_header = [
            Paragraph('<font size="8" color="#6A6A66">SDK NAME</font>',   s("th", alignment=TA_LEFT)),
            Paragraph('<font size="8" color="#6A6A66">CATEGORY</font>',   s("th", alignment=TA_LEFT)),
            Paragraph('<font size="8" color="#6A6A66">RISK SCORE</font>', s("th", alignment=TA_CENTER)),
            Paragraph('<font size="8" color="#6A6A66">RISK LEVEL</font>', s("th", alignment=TA_CENTER)),
        ]
        sdk_rows = [sdk_header]
        for sdk in sdks:
            rc = _risk_color(sdk["score"])
            level = "HIGH" if sdk["score"] >= 70 else ("MEDIUM" if sdk["score"] >= 45 else "LOW")
            sdk_rows.append([
                Paragraph(f'<font size="9" color="#1A1A18">{sdk["name"]}</font>', s("td")),
                Paragraph(f'<font size="9" color="#6A6A66">{sdk.get("risk", "").title()}</font>', s("td")),
                Paragraph(f'<font name="Helvetica-Bold" size="11" color="{rc.hexval()}">{sdk["score"]}</font>',
                          s("td_score", alignment=TA_CENTER)),
                Paragraph(f'<font size="8" color="{rc.hexval()}">{level}</font>',
                          s("td_level", alignment=TA_CENTER)),
            ])
        col_w = W - 2 * M
        style_cmds = [
            ("BACKGROUND",     (0, 0), (-1, 0),  _SURFACE2),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
            ("BOX",            (0, 0), (-1, -1), 0.5, _BORDER),
            ("INNERGRID",      (0, 0), (-1, -1), 0.3, _BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 7),
            ("LEFTPADDING",    (0, 0), (-1, -1), 10),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i, sdk in enumerate(sdks, start=1):
            rc = _risk_color(sdk["score"])
            style_cmds.append(("LINEAFTER", (0, i), (0, i), 2, rc))
        sdk_tbl = Table(sdk_rows, colWidths=[col_w * 0.38, col_w * 0.22, col_w * 0.2, col_w * 0.2])
        sdk_tbl.setStyle(TableStyle(style_cmds))
        story.append(sdk_tbl)
        story.append(Spacer(1, 6 * mm))

    # ── FINDINGS ──────────────────────────────────────────────────────────
    findings = report.get("findings", [])
    if findings:
        story.append(Paragraph(
            '<font name="Helvetica-Bold" size="12" color="#1A1A18">04 — Key Findings</font>',
            s("h2"),
        ))
        story.append(Spacer(1, 2 * mm))
        for f in findings:
            is_issue = f.get("kind") == "issue"
            dot_color = _TERRA if is_issue else _OLIVE
            title_color = "#B05A38" if is_issue else "#4A5E2A"
            row = [[
                Paragraph(f'<font name="Helvetica-Bold" size="18" color="{dot_color.hexval()}">•</font>',
                          s("dot", alignment=TA_CENTER)),
                Paragraph(
                    f'<font name="Helvetica-Bold" size="10" color="{title_color}">{f.get("title", "")}</font><br/>'
                    f'<font size="9" color="#6A6A66">{f.get("desc", "")}</font>',
                    s("finding_text", leading=15),
                ),
            ]]
            ft = Table(row, colWidths=[8 * mm, W - 2 * M - 8 * mm])
            ft.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), _SURFACE),
                ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ("LEFTPADDING",   (1, 0), (1, 0),   10),
            ]))
            story.append(ft)
            story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 4 * mm))

    # ── GDPR CHECKLIST ────────────────────────────────────────────────────
    story.append(Paragraph(
        '<font name="Helvetica-Bold" size="12" color="#1A1A18">05 — GDPR Compliance Checklist</font>',
        s("h2"),
    ))
    story.append(Spacer(1, 2 * mm))

    gdpr_items = report.get("gdpr_checklist") or [
        ("Data Minimisation",      "Collect only data strictly necessary for the stated purpose."),
        ("Privacy by Design",      "Privacy controls embedded in the product from the outset."),
        ("User Consent",           "Explicit opt-in consent obtained before any data processing."),
        ("Right to Erasure",       "Users can request full deletion of their personal data."),
        ("Data Breach Procedure",  "Documented procedure to notify authorities within 72 hours."),
        ("Third-Party Processors", "All SDK vendors are contractually bound to GDPR terms."),
    ]

    gdpr_header = [
        Paragraph('<font size="8" color="#6A6A66">ITEM</font>',        s("th")),
        Paragraph('<font size="8" color="#6A6A66">REQUIREMENT</font>', s("th")),
    ]
    gdpr_rows = [gdpr_header]
    for item, desc in gdpr_items:
        gdpr_rows.append([
            Paragraph(f'<font size="9" color="#4A5E2A">✓  {item}</font>', s("td")),
            Paragraph(f'<font size="8" color="#6A6A66">{desc}</font>', s("td")),
        ])
    col_w = W - 2 * M
    gdpr_tbl = Table(gdpr_rows, colWidths=[col_w * 0.28, col_w * 0.72])
    gdpr_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _SURFACE2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
        ("BOX",            (0, 0), (-1, -1), 0.5, _BORDER),
        ("INNERGRID",      (0, 0), (-1, -1), 0.3, _BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 7),
        ("LEFTPADDING",    (0, 0), (-1, -1), 10),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(gdpr_tbl)
    story.append(Spacer(1, 6 * mm))

    # ── DATA CATEGORIES ───────────────────────────────────────────────────
    cats = report.get("categories", [])
    if cats:
        story.append(Paragraph(
            '<font name="Helvetica-Bold" size="12" color="#1A1A18">06 — Data Collected by Category</font>',
            s("h2"),
        ))
        story.append(Spacer(1, 2 * mm))
        cat_rows = [[
            Paragraph('<font size="8" color="#6A6A66">CATEGORY</font>',    s("th")),
            Paragraph('<font size="8" color="#6A6A66">EXPOSURE</font>',    s("th")),
            Paragraph('<font size="8" color="#6A6A66">DESCRIPTION</font>', s("th")),
        ]]
        for c in cats:
            rc = _risk_color(int(c.get("amount", 0) * 100))
            cat_rows.append([
                Paragraph(f'<font size="9" color="#1A1A18">{c.get("cat", "")}</font>', s("td")),
                Paragraph(
                    f'<font name="Helvetica-Bold" size="9" color="{rc.hexval()}">'
                    f'{int(c.get("amount", 0) * 100)}%</font>',
                    s("td", alignment=TA_CENTER),
                ),
                Paragraph(f'<font size="8" color="#6A6A66">{c.get("desc", "")}</font>', s("td")),
            ])
        col_w = W - 2 * M
        cat_tbl = Table(cat_rows, colWidths=[col_w * 0.22, col_w * 0.12, col_w * 0.66])
        cat_tbl.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0),  _SURFACE2),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
            ("BOX",            (0, 0), (-1, -1), 0.5, _BORDER),
            ("INNERGRID",      (0, 0), (-1, -1), 0.3, _BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 7),
            ("LEFTPADDING",    (0, 0), (-1, -1), 10),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(cat_tbl)

    # ── FOOTER ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        '<font size="8" color="#6A6A66">Generated by Privacy Posture Analyzer  '
        '— Static analysis only. Results are indicative, not legal advice.</font>',
        s("footer", alignment=TA_CENTER),
    ))

    doc.build(story, onFirstPage=_bg_canvas, onLaterPages=_bg_canvas)
    return buf.getvalue()