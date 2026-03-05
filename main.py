import argparse
from collections import Counter

import pandas as pd


def find_col(df, candidates):
    cols = list(df.columns)
    for cand in candidates:
        for c in cols:
            if cand in c.lower():
                return c
    return None


def main(input_path: str, output_path: str):
    df = pd.read_csv(input_path)

    severity_col = find_col(df, ["severity", "risk", "risk factor"])
    name_col = find_col(df, ["name", "title", "plugin", "vulnerability"])
    host_col = find_col(df, ["host", "ip", "asset", "target"])

    lines = []
    lines.append("# Vulnerability scan summary\n")
    lines.append(f"Input file: {input_path}\n")
    lines.append(f"Total findings: {len(df)}\n")
    lines.append("")

    if severity_col:
        sev = df[severity_col].astype(str).str.strip().str.upper()
        sev = sev.replace({"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"})
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        counter = Counter(sev)

        lines.append("## Findings by severity")
        for s in order:
            lines.append(f"- {s}: {counter.get(s, 0)}")
        other = sum(counter.values()) - sum(counter.get(s, 0) for s in order)
        lines.append(f"- OTHER: {other}")
        lines.append("")

    if name_col:
        lines.append("## Top 10 vulnerabilities")
        top = df[name_col].astype(str).value_counts().head(10)
        for vuln, count in top.items():
            lines.append(f"- {vuln}: {count}")
        lines.append("")

    if host_col:
        lines.append("## Affected hosts (sample)")
        hosts = df[host_col].dropna().astype(str).unique()[:10]
        for h in hosts:
            lines.append(f"- {h}")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a summary report from a vulnerability scan CSV.")
    parser.add_argument("--input", "-i", required=True, help="Path to CSV input")
    parser.add_argument("--output", "-o", default="summary_report.md", help="Output report path")
    args = parser.parse_args()
    main(args.input, args.output)
