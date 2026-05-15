"""Negative and quality hardening tests for Phase 6."""

from __future__ import annotations

from pathlib import Path

import pytest

from hids_lab.baseline import load_baseline
from hids_lab.events import load_csv_events, load_events_file, load_json_events
from hids_lab.reports import build_report_data, render_markdown_report, write_report

ROOT = Path(__file__).resolve().parents[1]
HOST_EVENTS = ROOT / "samples" / "host_events"


def test_malformed_host_event_json_fails_clearly() -> None:
    with pytest.raises(ValueError, match="missing required fields"):
        load_json_events(HOST_EVENTS / "malformed_events.json")


def test_malformed_csv_fails_clearly(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("timestamp,host\n2026-01-15T00:00:00Z,lab-host-01\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required fields"):
        load_csv_events(path)


def test_malformed_baseline_fails_clearly(tmp_path: Path) -> None:
    path = tmp_path / "bad_baseline.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON baseline"):
        load_baseline(path)


def test_unsupported_report_format_fails_clearly(tmp_path: Path) -> None:
    report = build_report_data(title="Synthetic Empty Report", inputs={})

    with pytest.raises(ValueError, match="Unsupported report format"):
        write_report(report, tmp_path / "report.txt", report_format="html")


def test_unsupported_event_format_fails_clearly(tmp_path: Path) -> None:
    path = tmp_path / "events.txt"
    path.write_text("synthetic", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported event sample format"):
        load_events_file(path)


def test_empty_json_event_file_behavior(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("[]", encoding="utf-8")

    assert load_json_events(path) == []


def test_no_alert_report_behavior() -> None:
    report = build_report_data(
        title="Synthetic No-Alert Report",
        inputs={"events": "empty"},
        event_alerts=[],
        fim_findings=[],
        generated_at="2026-01-15T12:30:00Z",
    )
    markdown = render_markdown_report(report)

    assert "Total alerts: 0" in markdown
    assert "No file integrity findings included." in markdown
