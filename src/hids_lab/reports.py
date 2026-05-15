"""Markdown and JSON report generation for synthetic lab alerts."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hids_lab.alerts import Alert, fim_finding_to_alert
from hids_lab.suppressions import Suppression, apply_suppressions, count_suppressed

SAFETY_DISCLAIMER = (
    "Defensive lab-only report generated from synthetic local sample data. "
    "This project does not collect live endpoint telemetry, monitor real system paths, "
    "perform response actions, or claim production EDR/SIEM capability."
)


def build_report_data(
    *,
    title: str,
    inputs: dict[str, str],
    event_alerts: list[Alert] | None = None,
    fim_findings: list[dict[str, Any]] | None = None,
    suppressions: list[Suppression] | None = None,
    include_suppressed: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build the normalized report data structure."""
    generated_at = generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    event_alerts = event_alerts or []
    fim_findings = fim_findings or []
    fim_alerts = [fim_finding_to_alert(finding, timestamp=generated_at) for finding in fim_findings]
    all_alerts = [*event_alerts, *fim_alerts]
    full_alert_payloads = apply_suppressions(
        all_alerts,
        suppressions or [],
        include_suppressed=True,
    )
    alert_dicts = apply_suppressions(
        all_alerts,
        suppressions or [],
        include_suppressed=include_suppressed,
    )
    visible_event_alerts = apply_suppressions(
        event_alerts,
        suppressions or [],
        include_suppressed=include_suppressed,
    )
    severity_counts = dict(Counter(str(alert["severity"]) for alert in alert_dicts))
    suppression_counts = count_suppressed(full_alert_payloads)

    return {
        "metadata": {
            "title": title,
            "generated_at": generated_at,
            "synthetic": True,
        },
        "summary": {
            "total_alerts": len(alert_dicts),
            "event_detection_count": len(visible_event_alerts),
            "fim_finding_count": len(fim_findings),
            "suppressed_alert_count": suppression_counts["suppressed"],
            "unsuppressed_alert_count": suppression_counts["unsuppressed"],
        },
        "severity_counts": severity_counts,
        "alerts": alert_dicts,
        "fim_findings": fim_findings,
        "event_detections": visible_event_alerts,
        "inputs": inputs,
        "safety_disclaimer": SAFETY_DISCLAIMER,
    }


def render_json_report(report: dict[str, Any]) -> str:
    """Render report data as stable JSON."""
    return json.dumps(report, indent=2) + "\n"


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render report data as Markdown."""
    metadata = report["metadata"]
    summary = report["summary"]
    lines = [
        f"# {metadata['title']}",
        "",
        f"Generated: {metadata['generated_at']}",
        "",
        "## Safety Disclaimer",
        "",
        report["safety_disclaimer"],
        "",
        "## Input Sources",
        "",
    ]
    for name, value in report["inputs"].items():
        lines.append(f"- {name}: `{value}`")

    lines.extend(
        [
            "",
            "## Executive Summary",
            "",
            f"- Total alerts: {summary['total_alerts']}",
            f"- Host-event detections: {summary['event_detection_count']}",
            f"- File integrity findings: {summary['fim_finding_count']}",
            f"- Suppressed alerts: {summary['suppressed_alert_count']}",
            "",
            "## Alert Count By Severity",
            "",
        ]
    )
    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"- {severity}: {report['severity_counts'].get(severity, 0)}")

    lines.extend(
        [
            "",
            "## File Integrity Findings Summary",
            "",
            *render_fim_summary_lines(report["fim_findings"]),
            "",
            "## Host-Event Detections Summary",
            "",
            f"- Host-event alerts: {len(report['event_detections'])}",
            "",
            "## Detailed Alert Table",
            "",
            "| Severity | Rule | Title | Evidence | Recommended Action |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for alert in report["alerts"]:
        lines.append(
            "| {severity} | {rule_id} | {title} | {evidence} | {action} |".format(
                severity=escape_table_cell(str(alert["severity"])),
                rule_id=escape_table_cell(str(alert["rule_id"])),
                title=escape_table_cell(str(alert["title"])),
                evidence=escape_table_cell(str(alert["evidence"])),
                action=escape_table_cell(str(alert["recommended_action"])),
            )
        )

    lines.extend(
        [
            "",
            "## Triage Recommendations",
            "",
            "- Review high-severity synthetic findings first.",
            "- Confirm all paths reference local lab sample files.",
            "- Use the evidence field to explain why each rule matched.",
            "- Document analyst notes separately from generated output.",
            "",
            "## Limitations",
            "",
            "- Synthetic-only lab report.",
            "- No live endpoint telemetry collection.",
            "- No production EDR/SIEM capability is claimed.",
            "- No response or file changes are performed.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_path: Path, *, report_format: str) -> None:
    """Write a Markdown or JSON report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if report_format == "json":
        content = render_json_report(report)
    elif report_format == "markdown":
        content = render_markdown_report(report)
    else:
        msg = f"Unsupported report format: {report_format}"
        raise ValueError(msg)
    output_path.write_text(content, encoding="utf-8")


def render_fim_summary_lines(fim_findings: list[dict[str, Any]]) -> list[str]:
    """Render a compact FIM status summary."""
    if not fim_findings:
        return ["- No file integrity findings included."]
    counts = Counter(str(finding["status"]) for finding in fim_findings)
    statuses = ("modified", "added", "deleted", "unchanged")
    return [f"- {status}: {counts.get(status, 0)}" for status in statuses]


def escape_table_cell(value: str) -> str:
    """Escape Markdown table separators."""
    return value.replace("|", "\\|").replace("\n", " ")
