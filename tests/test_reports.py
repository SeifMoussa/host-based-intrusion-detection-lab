"""Tests for Phase 5 report generation."""

from __future__ import annotations

import json
from pathlib import Path

from hids_lab.baseline import create_baseline
from hids_lab.cli import main
from hids_lab.detections import detect_events
from hids_lab.events import load_json_events
from hids_lab.fim import compare_to_baseline
from hids_lab.reports import (
    SAFETY_DISCLAIMER,
    build_report_data,
    render_json_report,
    render_markdown_report,
)
from hids_lab.safety import find_public_ipv4_addresses, find_unreserved_domains
from hids_lab.suppressions import load_suppressions

ROOT = Path(__file__).resolve().parents[1]
HOST_EVENTS = ROOT / "samples" / "host_events"
SAMPLE_CLEAN = ROOT / "samples" / "files" / "clean"
GENERATED_AT = "2026-01-15T12:30:00Z"


def test_markdown_event_report_generation() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    report = build_report_data(
        title="Synthetic Event Report",
        inputs={"events": "samples/host_events/suspicious_events.json"},
        event_alerts=alerts,
        generated_at=GENERATED_AT,
    )
    markdown = render_markdown_report(report)

    assert "# Synthetic Event Report" in markdown
    assert "## Detailed Alert Table" in markdown
    assert "HIDS-FILE-001" in markdown


def test_json_event_report_generation() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    report = build_report_data(
        title="Synthetic Event Report",
        inputs={"events": "samples/host_events/suspicious_events.json"},
        event_alerts=alerts,
        generated_at=GENERATED_AT,
    )
    payload = json.loads(render_json_report(report))

    assert payload["metadata"]["title"] == "Synthetic Event Report"
    assert payload["summary"]["event_detection_count"] == len(alerts)
    assert payload["alerts"]


def test_fim_report_generation() -> None:
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT, generated_at=GENERATED_AT)
    findings = compare_to_baseline(baseline, SAMPLE_CLEAN, repo_root=ROOT)
    report = build_report_data(
        title="Synthetic FIM Report",
        inputs={"baseline": "generated", "root": "samples/files/clean"},
        fim_findings=findings,
        generated_at=GENERATED_AT,
    )

    markdown = render_markdown_report(report)
    assert "File Integrity Findings Summary" in markdown
    assert "unchanged: 3" in markdown


def test_combined_report_generation() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT, generated_at=GENERATED_AT)
    findings = compare_to_baseline(baseline, SAMPLE_CLEAN, repo_root=ROOT)
    report = build_report_data(
        title="Synthetic Combined Report",
        inputs={"events": "suspicious", "baseline": "generated", "root": "clean"},
        event_alerts=alerts,
        fim_findings=findings,
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["event_detection_count"] == len(alerts)
    assert report["summary"]["fim_finding_count"] == len(findings)
    assert report["summary"]["total_alerts"] == len(alerts) + len(findings)


def test_severity_counts() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    report = build_report_data(
        title="Synthetic Event Report",
        inputs={"events": "suspicious"},
        event_alerts=alerts,
        generated_at=GENERATED_AT,
    )

    assert report["severity_counts"]["high"] == 1
    assert report["severity_counts"]["medium"] == 2


def test_report_includes_safety_disclaimer_and_triage_recommendations() -> None:
    report = build_report_data(
        title="Synthetic Empty Report",
        inputs={},
        generated_at=GENERATED_AT,
    )
    markdown = render_markdown_report(report)

    assert SAFETY_DISCLAIMER in markdown
    assert "Triage Recommendations" in markdown


def test_report_includes_host_event_detections_and_fim_findings() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT, generated_at=GENERATED_AT)
    findings = compare_to_baseline(baseline, SAMPLE_CLEAN, repo_root=ROOT)
    report = build_report_data(
        title="Synthetic Combined Report",
        inputs={"events": "suspicious", "baseline": "generated", "root": "clean"},
        event_alerts=alerts,
        fim_findings=findings,
        generated_at=GENERATED_AT,
    )

    assert report["event_detections"]
    assert report["fim_findings"]


def test_report_has_no_real_world_indicators() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    report = build_report_data(
        title="Synthetic Event Report",
        inputs={"events": "samples/host_events/suspicious_events.json"},
        event_alerts=alerts,
        generated_at=GENERATED_AT,
    )
    content = render_markdown_report(report)

    assert find_public_ipv4_addresses(content) == set()
    assert find_unreserved_domains(content) == set()


def test_cli_report_events_works(tmp_path: Path, capsys) -> None:
    output = tmp_path / "events_report.md"
    exit_code = main(
        [
            "report",
            "events",
            "--input",
            str(HOST_EVENTS / "suspicious_events.json"),
            "--output",
            str(output),
            "--format",
            "markdown",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "written"
    assert "HIDS-FILE-001" in output.read_text(encoding="utf-8")


def test_cli_report_fim_works(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["baseline", "create", "--root", str(SAMPLE_CLEAN), "--output", str(baseline)]) == 0
    capsys.readouterr()
    output = tmp_path / "fim_report.md"

    exit_code = main(
        [
            "report",
            "fim",
            "--baseline",
            str(baseline),
            "--root",
            str(SAMPLE_CLEAN),
            "--output",
            str(output),
            "--format",
            "markdown",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "written"
    assert "File Integrity Findings Summary" in output.read_text(encoding="utf-8")


def test_cli_report_combined_works(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["baseline", "create", "--root", str(SAMPLE_CLEAN), "--output", str(baseline)]) == 0
    capsys.readouterr()
    output = tmp_path / "combined_report.json"

    exit_code = main(
        [
            "report",
            "combined",
            "--events",
            str(HOST_EVENTS / "suspicious_events.json"),
            "--baseline",
            str(baseline),
            "--root",
            str(SAMPLE_CLEAN),
            "--output",
            str(output),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "written"
    assert payload["summary"]["event_detection_count"] > 0
    assert payload["summary"]["fim_finding_count"] == 3


def test_report_counts_suppressed_alerts() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "false_positive_events.json"))
    suppressions = load_suppressions(ROOT / "suppressions" / "example_suppressions.json")
    report = build_report_data(
        title="Synthetic Suppression Report",
        inputs={"events": "false_positive_events.json"},
        event_alerts=alerts,
        suppressions=suppressions,
        include_suppressed=True,
        generated_at=GENERATED_AT,
    )

    assert report["summary"]["suppressed_alert_count"] == 1
    assert any(alert["suppressed"] is True for alert in report["alerts"])
