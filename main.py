import argparse
import os
from pathlib import Path
from datetime import datetime

import pandas as pd

# ---- CSV column aliases (Nessus/OpenVAS/etc.) ----
COLUMN_ALIASES = {
    "title": ["Name", "Plugin Name", "Title", "Vulnerability", "Finding"],
    "severity": ["Severity", "Risk", "Risk Level", "CVSS Severity"],
    "host": ["Host", "IP", "IP Address", "Hostname"],
    "port": ["Port", "Service Port"],
    "cve": ["CVE", "CVE IDs", "CVE Id"],
    "description": ["Description", "Synopsis", "Details"],
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def find_column(df: pd.DataFrame, logical_name: str) -> str | None:
    for c in COLUMN_ALIASES.get(logical_name, []):
        if c in df.columns:
            return c
    return None


def normalise_severity(val: str) -> str:
    if pd.isna(val):
        return "Info"
    v = str(val).strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
        "none": "Info",
    }
    # handle numeric severities (0–10) if present
    try:
        num = float(v)
        if num >= 9.0:
            return "Critical"
        if num >= 7.0:
            return "High"
        if num >= 4.0:
            return "Medium"
        if num > 0.0:
            return "Low"
        return "Info"
    except Exception:
        return mapping.get(v, str(val).strip().title())


# -------- AI explanation (optional API; safe fallback if no key) --------
def fallback_ai_explanation(title: str, severity: str, cve: str | None, description: str | None) -> str:
    cve_txt = f" CVE: {cve}." if cve and cve.strip() else ""
    desc_hint = ""
    if description and isinstance(description, str) and description.strip():
        desc_hint = f" Context: {description.strip()[:220]}..."

    fix_hint = {
        "Critical": "Patch/upgrade immediately, validate exposure, and consider compensating controls (WAF, segmentation).",
        "High": "Prioritise patching, restrict access, and confirm exploitability in your environment.",
        "Medium": "Schedule remediation, harden configs, and monitor for exploitation attempts.",
        "Low": "Fix when convenient; treat as hygiene and reduce attack surface.",
        "Info": "Informational: track and validate whether it matters to your environment.",
    }.get(severity, "Validate impact, then remediate appropriately.")

    impact_hint = {
        "Critical": "Likely enables full compromise or major data exposure.",
        "High": "Often enables serious compromise if reachable or chained with other issues.",
        "Medium": "Meaningful weakness, but usually needs conditions or chaining.",
        "Low": "Minor weakness or limited impact.",
        "Info": "Not a vulnerability by itself; useful context for security posture.",
    }.get(severity, "Potential security risk depending on exposure.")

    extra = f"\n**Extra context:** {desc_hint}" if desc_hint else ""
    return f"**Why it matters:** {impact_hint}{cve_txt}\n**Recommended fix:** {fix_hint}{extra}".strip()


def openai_ai_explanation(title: str, severity: str, cve: str | None, description: str | None, model: str) -> str:
    """
    Uses OpenAI if OPENAI_API_KEY is set.
    If anything fails, returns fallback.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return fallback_ai_explanation(title, severity, cve, description)

    try:
        from openai import OpenAI  # type: ignore
        client = OpenAI(api_key=api_key)

        prompt = f"""
You are helping a junior cybersecurity analyst write a recruiter-friendly vulnerability report.

Write a short explanation for ONE finding with:
1) Why it matters (impact in plain English)
2) How attackers could exploit it (high level, non-instructional)
3) Recommended fix (actionable steps)
4) 1 verification step (how to confirm it's fixed)

Keep it concise and professional.

Finding title: {title}
Severity: {severity}
CVE(s): {cve or "N/A"}
Description/Synopsis: {description or "N/A"}
"""
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You write concise, professional security report text."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        text = (resp.choices[0].message.content or "").strip()
        if not text:
            return fallback_ai_explanation(title, severity, cve, description)
        return text
    except Exception:
        return fallback_ai_explanation(title, severity, cve, description)


# -------- PDF Export (ReportLab) --------
def export_pdf(pdf_path: str, title: str, counts_sorted: dict, top_rows: list[dict], include_ai: bool):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path, pagesize=A4, title=title)
    story = []

    story.append(Paragraph(title, styles["Title"]))
    story.append(Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M"), styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Counts by severity", styles["Heading2"]))
    counts_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in counts_sorted.items()]
    t = Table(counts_data, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Top findings (first 15)", styles["Heading2"]))
    top_data = [["Severity", "Finding", "Host", "Port", "CVE"]]
    for r in top_rows:
        top_data.append([r["sev"], r["finding"], r["host"], r["port"], r["cve"]])
    t2 = Table(top_data, colWidths=[60, 220, 110, 40, 90], hAlign="LEFT")
    t2.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t2)

    if include_ai:
        story.append(PageBreak())
        story.append(Paragraph("AI Explanations (recruiter-friendly)", styles["Heading2"]))
        story.append(Spacer(1, 8))
        for i, r in enumerate(top_rows, 1):
            story.append(Paragraph(f"{i}. {r['sev']} — {r['finding']}", styles["Heading3"]))
            ai_html = (r.get("ai") or "").replace("\n", "<br/>")
            story.append(Paragraph(ai_html, styles["BodyText"]))
            story.append(Spacer(1, 10))

    doc.build(story)


def main():
    ap = argparse.ArgumentParser(description="Summarise vulnerability CSV exports into a simple report.")
    ap.add_argument("--input", required=True, help="Path to CSV export (e.g., Nessus/OpenVAS CSV)")
    ap.add_argument("--out", default="summary_report.md", help="Output markdown report path")
    ap.add_argument("--pdf", default=None, help="Optional PDF output path (e.g., report.pdf)")
    ap.add_argument("--ai", action="store_true", help="Add recruiter-friendly AI explanations per top finding")
    ap.add_argument("--model", default="gpt-4.1-mini", help="OpenAI model (used only if OPENAI_API_KEY is set)")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise SystemExit(f"Input file not found: {in_path}")

    df = pd.read_csv(in_path)

    col_title = find_column(df, "title")
    col_sev = find_column(df, "severity")
    col_host = find_column(df, "host")
    col_port = find_column(df, "port")
    col_cve = find_column(df, "cve")
    col_desc = find_column(df, "description")

    if not col_title or not col_sev:
        raise SystemExit(
            "Couldn't find required columns for Title and Severity.\n"
            f"Columns found: {list(df.columns)}\n"
            "Update COLUMN_ALIASES in main.py to match your CSV headers."
        )

    df["Severity_Normalised"] = df[col_sev].apply(normalise_severity)

    counts = df["Severity_Normalised"].value_counts().to_dict()
    counts_sorted = {k: counts.get(k, 0) for k in SEVERITY_ORDER}

    print("Counts by severity:")
    for k, v in counts_sorted.items():
        print(f"  {k:8} {v}")

    df["Severity_Rank"] = df["Severity_Normalised"].apply(
        lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER)
    )
    top = df.sort_values(["Severity_Rank"]).head(15)

    top_rows = []
    for _, row in top.iterrows():
        sev = row["Severity_Normalised"]
        finding = str(row.get(col_title, "")).strip()
        host = str(row.get(col_host, "")) if col_host else ""
        port = str(row.get(col_port, "")) if col_port else ""
        cve = str(row.get(col_cve, "")) if col_cve else ""
        desc = str(row.get(col_desc, "")) if col_desc else ""

        ai_text = ""
        if args.ai:
            ai_text = openai_ai_explanation(
                title=finding,
                severity=sev,
                cve=cve if cve else None,
                description=desc if desc else None,
                model=args.model,
            )

        top_rows.append({
            "sev": sev,
            "finding": finding,
            "host": host,
            "port": port,
            "cve": cve,
            "desc": desc,
            "ai": ai_text,
        })

    out_lines = []
    out_lines.append("# Vulnerability Summary Report\n\n")
    out_lines.append(f"**Input:** `{in_path.name}`\n\n")
    out_lines.append("## Counts by severity\n\n")
    out_lines.append("| Severity | Count |\n|---|---:|\n")
    for k, v in counts_sorted.items():
        out_lines.append(f"| {k} | {v} |\n")

    out_lines.append("\n## Top findings (first 15)\n\n")
    out_lines.append("| Severity | Finding | Host | Port | CVE |\n|---|---|---|---:|---|\n")
    for r in top_rows:
        out_lines.append(f"| {r['sev']} | {r['finding']} | {r['host']} | {r['port']} | {r['cve']} |\n")

    if args.ai:
        out_lines.append("\n## AI explanations (recruiter-friendly)\n\n")
        for i, r in enumerate(top_rows, 1):
            out_lines.append(f"### {i}. {r['sev']} — {r['finding']}\n\n")
            out_lines.append((r["ai"] or "").strip() + "\n\n")

    out_lines.append("## Notes\n")
    out_lines.append("This report is auto-generated. Validate findings in your scanner and apply remediation per your environment.\n")

    Path(args.out).write_text("".join(out_lines), encoding="utf-8")
    print(f"\nWrote markdown report to: {args.out}")

    if args.pdf:
        export_pdf(args.pdf, "Vulnerability Summary Report", counts_sorted, top_rows, include_ai=args.ai)
        print(f"Wrote PDF report to: {args.pdf}")


if __name__ == "__main__":
    main()
