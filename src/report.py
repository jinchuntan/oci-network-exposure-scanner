import json
from datetime import datetime
from pathlib import Path


def ts_utc():
    return datetime.utcnow().strftime("%Y-%m-%d_%H%M%S_UTC")


def write_json(findings, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def write_md(findings, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("# OCI Network Exposure Scan Report")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append(f"Total findings: **{len(findings)}**")
    lines.append("")
    lines.append("| Type | Resource | Ports | Risk | Note |")
    lines.append("|---|---|---:|---|---|")
    for f in findings:
        lines.append(
            f"| {f['resource_type']} | {f['resource_name']} | {f['ports']} | {f['risk']} | {f['note']} |"
        )
    out_path.write_text("\n".join(lines), encoding="utf-8")
