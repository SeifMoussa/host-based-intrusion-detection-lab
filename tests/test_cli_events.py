"""CLI tests for synthetic host-event validation and detection."""

from __future__ import annotations

import json
from pathlib import Path

from hids_lab.cli import main

ROOT = Path(__file__).resolve().parents[1]
HOST_EVENTS = ROOT / "samples" / "host_events"


def test_cli_events_validate_works(capsys) -> None:
    exit_code = main(["events", "validate", "--input", str(HOST_EVENTS / "clean_events.json")])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload == {"status": "valid", "event_count": 2}


def test_cli_events_detect_json_works(capsys) -> None:
    exit_code = main(
        [
            "events",
            "detect",
            "--input",
            str(HOST_EVENTS / "suspicious_events.json"),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["total"] > 0
    assert "HIDS-FILE-001" in {alert["rule_id"] for alert in payload["alerts"]}


def test_cli_events_detect_text_works(capsys) -> None:
    exit_code = main(
        [
            "events",
            "detect",
            "--input",
            str(HOST_EVENTS / "mixed_events.csv"),
            "--format",
            "text",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "alerts:" in captured.out
    assert "HIDS-AUTH-001" in captured.out


def test_cli_invalid_event_input_fails_safely(capsys) -> None:
    exit_code = main(["events", "validate", "--input", str(HOST_EVENTS / "missing.json")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "does not exist" in captured.err


def test_cli_events_detect_with_suppressions(capsys) -> None:
    exit_code = main(
        [
            "events",
            "detect",
            "--input",
            str(HOST_EVENTS / "false_positive_events.json"),
            "--suppressions",
            str(ROOT / "suppressions" / "example_suppressions.json"),
            "--format",
            "json",
            "--include-suppressed",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["suppressed"] == 1
    assert any(alert["suppression_id"] == "SUP-001" for alert in payload["alerts"])


def test_cli_malformed_event_input_fails_safely(capsys) -> None:
    exit_code = main(["events", "validate", "--input", str(HOST_EVENTS / "malformed_events.json")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "missing required fields" in captured.err
