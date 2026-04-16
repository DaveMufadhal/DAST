import re
from html import unescape
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Flowable, KeepTogether
)
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from collections import defaultdict, Counter


def sanitize_html_for_pdf(text):
    """Clean HTML content for PDF generation"""
    if not isinstance(text, str):
        return str(text) if text is not None else "-"

    text = re.sub(r'<[^>]+>', '', text)

    text = unescape(text)

    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')

    text = re.sub(r'\s+', ' ', text).strip()

    if len(text) > 1000:
        text = text[:997] + "..."

    return text or "-"


BG_DARK = colors.HexColor("#0b1020")
CARD_DARK = colors.HexColor("#121832")
TEXT = colors.HexColor("#0b0f1a")
MUTED = colors.HexColor("#475569")
BORDER = colors.HexColor("#e2e8f0")
ACCENT1 = colors.HexColor("#6ee7f3")
ACCENT2 = colors.HexColor("#a78bfa")

SEV_COLORS = {
    "high": colors.HexColor("#ef4444"),
    "medium": colors.HexColor("#f59e0b"),
    "low": colors.HexColor("#10b981"),
    "info": colors.HexColor("#64748b"),
}


def sev_bucket(score: int) -> str:
    if score <= 0:
        return "info"
    if 1 <= score <= 2:
        return "low"
    if 3 <= score <= 5:
        return "medium"
    return "high"


def dot(radius=2, fill=colors.black):
    class Dot(Flowable):
        def __init__(self):
            Flowable.__init__(self)
            self.radius = radius
            self.fill = fill

        def wrap(self, availWidth, availHeight):
            return (self.radius * 2, self.radius * 2)

        def draw(self):
            self.canv.setFillColor(self.fill)
            self.canv.circle(self.radius, self.radius, self.radius, stroke=0, fill=1)

    return Dot()


class Pill(Flowable):
    """Rounded label 'pill' with colored dot."""

    def __init__(self, text, color=colors.HexColor("#64748b"),
                 txt_color=TEXT, padding=3, r=5):
        Flowable.__init__(self)
        self.text = text
        self.color = color
        self.txt_color = txt_color
        self.padding = padding
        self.radius = r

    def wrap(self, availWidth, availHeight):
        w = len(self.text) * 6 + self.padding * 2 + 20
        h = 12 + self.padding * 2
        return (min(w, availWidth), h)

    def draw(self):
        w, h = self.wrap(0, 0)

        self.canv.setFillColor(self.color)
        self.canv.setStrokeColor(self.color)
        self.canv.roundRect(0, 0, w, h, self.radius, stroke=1, fill=1)

        dot_x = self.padding + 3
        dot_y = h // 2
        self.canv.setFillColor(colors.white)
        self.canv.circle(dot_x, dot_y, 2, stroke=0, fill=1)

        self.canv.setFillColor(colors.white)
        self.canv.setFont("Helvetica-Bold", 8)
        text_x = dot_x + 8
        text_y = dot_y - 3
        self.canv.drawString(text_x, text_y, self.text)


def draw_header_footer(canvas: pdfcanvas.Canvas, doc):
    page = canvas.getPageNumber()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(doc.pagesize[0] - 15 * mm, 12 * mm, f"Page {page}")


def draw_cover(canvas: pdfcanvas.Canvas, doc, title, subtitle, meta):
    W, H = doc.pagesize
    canvas.saveState()

    canvas.setFillColor(colors.white)
    canvas.rect(0, 0, W, H, stroke=0, fill=1)

    canvas.setFillColor(ACCENT1)
    canvas.setFillAlpha(0.12)
    canvas.circle(0.15 * W, 1.05 * H, 0.6 * W, stroke=0, fill=1)

    canvas.setFillColor(ACCENT2)
    canvas.setFillAlpha(0.12)
    canvas.circle(0.85 * W, 1.05 * H, 0.6 * W, stroke=0, fill=1)

    canvas.setFillAlpha(1)

    x, y, w, h = 50 * mm, H // 2 - 50 * mm, W - 100 * mm, 100 * mm
    canvas.setFillColor(colors.white)
    canvas.setStrokeColor(BORDER)
    canvas.roundRect(x, y, w, h, 8, stroke=1, fill=1)

    canvas.setFillColor(colors.HexColor("#f1f5f9"))
    canvas.setStrokeColor(BORDER)
    canvas.roundRect(x + 8, y + h - 16, 60, 14, 7, stroke=1, fill=1)
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(MUTED)
    canvas.drawString(x + 14, y + h - 12, "Mini-OWASP Scanner")

    canvas.setFont("Helvetica-Bold", 22)
    canvas.setFillColor(TEXT)
    canvas.drawString(x + 14, y + h - 34, title)

    canvas.setFont("Helvetica", 11)
    canvas.setFillColor(MUTED)
    canvas.drawString(x + 14, y + h - 50, subtitle)

    canvas.setFont("Helvetica", 10)
    yy = y + h - 70
    for line in meta:
        canvas.drawString(x + 14, yy, line)
        yy -= 14

    # Accent bar
    canvas.setFillColor(ACCENT1)
    canvas.rect(x + 14, y + 16, w - 28, 3, stroke=0, fill=1)

    canvas.restoreState()


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=14, textColor=TEXT, spaceAfter=4))
    ss.add(ParagraphStyle(name="H3", fontName="Helvetica-Bold", fontSize=12, textColor=TEXT, spaceAfter=2))
    ss.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9, textColor=TEXT, leading=11))
    ss.add(ParagraphStyle(name="BodySmall", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=10))
    return ss


def _card_table(rows, col_widths=None, bg=colors.white):
    if not col_widths:
        col_widths = [25 * mm, 120 * mm]

    tbl = Table(rows, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), TEXT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl


def _stat_card(value, label):
    return _card_table([
        [Paragraph(f"<b>{value}</b>", _styles()["H2"]), ""],
        [Paragraph(label, _styles()["BodySmall"]), ""]
    ], col_widths=[40 * mm, 5 * mm])


def to_pdf(findings: list, generated_at: str, pdf_path: str, title="Security Assessment Report"):
    """Generate a professional PDF report from findings"""

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm
    )

    story = []
    styles = _styles()

    total = len(findings)
    by_severity = Counter(sev_bucket(f.get("severity_score", 0)) for f in findings)
    by_type = Counter(f.get("type", "unknown").split(":")[0] for f in findings)

    def cover_page(canvas, doc):
        draw_cover(canvas, doc, title, "Automated Vulnerability Assessment", [
            f"Generated: {datetime.fromisoformat(generated_at.replace('Z', '+00:00')).strftime('%B %d, %Y at %H:%M UTC')}",
            f"Total Issues: {total}",
            f"High: {by_severity.get('high', 0)} | Medium: {by_severity.get('medium', 0)} | Low: {by_severity.get('low', 0)}"
        ])

    story.append(Paragraph("Executive Summary", styles["H2"]))
    story.append(Spacer(1, 4 * mm))

    stats_data = [
        [_stat_card(total, "Total Issues"), _stat_card(by_severity.get('high', 0), "High Risk")],
        [_stat_card(by_severity.get('medium', 0), "Medium Risk"), _stat_card(by_severity.get('low', 0), "Low Risk")]
    ]
    stats_table = Table(stats_data, colWidths=[75 * mm, 75 * mm])
    stats_table.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 8 * mm))

    if total > 0:
        risk_level = "HIGH" if by_severity.get('high', 0) > 0 else (
            "MEDIUM" if by_severity.get('medium', 0) > 0 else "LOW")
        summary_text = f"""
        This automated security assessment identified {total} potential vulnerabilities across the target application.
        The overall risk level is assessed as <b>{risk_level}</b>.
        Priority should be given to addressing high-severity issues first, followed by medium and low-severity findings.
        """
    else:
        summary_text = "No significant security vulnerabilities were identified during this automated assessment."

    story.append(Paragraph(summary_text.strip(), styles["Body"]))
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["H2"]))
    story.append(Spacer(1, 6 * mm))

    if not findings:
        story.append(Paragraph("No vulnerabilities were found.", styles["Body"]))
    else:

        by_category = defaultdict(list)
        for f in findings:
            category = f.get("type", "unknown").split(":")[0]
            by_category[category].append(f)

        for category, items in by_category.items():

            safe_category = sanitize_html_for_pdf(category).title().replace('_', ' ')
            story.append(Paragraph(f"{safe_category} ({len(items)} issues)", styles["H3"]))

            story.append(Spacer(1, 3 * mm))

            items.sort(key=lambda x: -x.get("severity_score", 0))

            for it in items:
                sev = sev_bucket(it.get("severity_score", 0))
                pills = [
                    Pill(sev.capitalize(), SEV_COLORS.get(sev, SEV_COLORS["info"])),
                    Pill(f"Score {it.get('severity_score', 0)}", SEV_COLORS["info"])
                ]
                pills_tbl = Table([pills])
                pills_tbl.setStyle(TableStyle([
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]))

                # Format CWE IDs
                cwe_text = ", ".join(it.get("cwe_ids", [])[:2]) if it.get("cwe_ids") else "-"

                # Format References as clickable links
                refs = it.get("references", [])
                ref_links = []
                for ref in refs[:2]:
                    ref_url = ref.get("url", "")
                    if ref_url:
                        ref_links.append(f'<a href="{ref_url}">{ref_url}</a>')
                ref_text = ", ".join(ref_links) if ref_links else "-"

                # In the findings loop section (around line 260-280), add AI analysis display

                # After the "Recommendation" row, add:
                rows = [
                    ["URL", Paragraph(sanitize_html_for_pdf(it.get("url")), styles["Body"])],
                    ["Param", Paragraph(sanitize_html_for_pdf(it.get("param")), styles["Body"])],
                    ["Payload", Paragraph(sanitize_html_for_pdf(it.get("payload")), styles["Body"])],
                    ["Evidence", Paragraph(sanitize_html_for_pdf(it.get("evidence")), styles["Body"])],
                    ["CWE ID", Paragraph(sanitize_html_for_pdf(cwe_text), styles["Body"])],
                    ["References", Paragraph(ref_text, styles["Body"])],
                    ["Recommendation",
                     Paragraph(sanitize_html_for_pdf(it.get("recommendation")) or "Follow OWASP best practices.",
                               styles["Body"])],
                ]

                # ADD THIS SECTION FOR AI ANALYSIS:
                if it.get("ai_analysis"):
                    ai = it.get("ai_analysis")
                    rows.append(["AI Analysis", ""])  # Section header

                    if ai.get("vulnerability_explanation"):
                        rows.append(["Vulnerability Explanation",
                                     Paragraph(sanitize_html_for_pdf(ai.get("vulnerability_explanation")),
                                               styles["Body"])])

                    if ai.get("attack_scenario"):
                        rows.append(["Attack Scenario",
                                     Paragraph(sanitize_html_for_pdf(ai.get("attack_scenario")), styles["Body"])])

                    if ai.get("impact"):
                        rows.append(["Impact",
                                     Paragraph(sanitize_html_for_pdf(ai.get("impact")), styles["Body"])])

                    if ai.get("mitigation_steps"):
                        steps = ", ".join(ai.get("mitigation_steps", [])[:3])
                        rows.append(["Mitigation Steps",
                                     Paragraph(sanitize_html_for_pdf(steps), styles["Body"])])

                    if ai.get("code_mitigation"):
                        rows.append(["Code Mitigation Example",
                                     Paragraph(sanitize_html_for_pdf(ai.get("code_mitigation")), styles["Body"])])

                    if ai.get("tools_to_use"):
                        tools = ", ".join(ai.get("tools_to_use", [])[:3])
                        rows.append(["Recommended Tools",
                                     Paragraph(sanitize_html_for_pdf(tools), styles["Body"])])

                # Rest of the code continues...
                card = _card_table(rows)
                story.append(KeepTogether([pills_tbl, Spacer(1, 2 * mm), card, Spacer(1, 6 * mm)]))

    # Methodology
    story.append(PageBreak())
    story.append(Paragraph("Methodology", styles["H2"]))
    story.append(Spacer(1, 4 * mm))

    methodology_text = """
    This assessment was conducted using an automated web application security scanner that performs:

    • <b>Passive Analysis:</b> Security header analysis, cookie security assessment, CORS policy review
    • <b>Active Testing:</b> SQL injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI) testing
    • <b>Authentication Testing:</b> Session management analysis, authentication bypass attempts
    • <b>Configuration Review:</b> CSRF protection analysis, server misconfiguration detection

    All tests were performed with rate limiting to minimize impact on the target application.
    Results should be manually verified before remediation efforts begin.
    """

    story.append(Paragraph(methodology_text.strip(), styles["Body"]))

    doc.build(story, onFirstPage=cover_page, onLaterPages=draw_header_footer)

    print(f"✅ PDF report generated: {pdf_path}")