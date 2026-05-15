"""Tests for explicit synthetic alert suppressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from hids_lab.detections import detect_events
from hids_lab.events import load_json_events
from hids_lab.suppressions import apply_suppressions, load_suppressions

ROOT = Path(__file__).resolve().parents[1]
HOST_EVENTS = ROOT / "samples" / "host_events"
SUPPRESSIONS = ROOT / "suppressions" / "example_suppressions.json"


def test_load_suppressions() -> None:
    suppressions = load_suppressions(SUPPRESSIONS)

    assert len(suppressions) == 1
    assert suppressions[0].id == "SUP-001"


def test_apply_suppressions_hides_suppressed_alerts_by_default() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "false_positive_events.json"))
    suppressions = load_suppressions(SUPPRESSIONS)

    visible = apply_suppressions(alerts, suppressions)

    assert all(alert["rule_id"] != "HIDS-AUTH-001" for alert in visible)


def test_apply_suppressions_can_include_suppressed_alerts() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "false_positive_events.json"))
    suppressions = load_suppressions(SUPPRESSIONS)

    visible = apply_suppressions(alerts, suppressions, include_suppressed=True)
    suppressed = [alert for alert in visible if alert["suppressed"] is True]

    assert len(suppressed) == 1
    assert suppressed[0]["suppression_id"] == "SUP-001"
    assert suppressed[0]["suppression_reason"]
    assert suppressed[0]["evidence"] == "user=lab_user; count=2"


def test_invalid_suppression_file_fails_clearly(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid suppression JSON"):
        load_suppressions(path)


def test_invalid_suppression_schema_fails_clearly(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"suppressions": [{"id": "SUP-001"}]}', encoding="utf-8")

    with pytest.raises(ValueError, match="missing fields"):
        load_suppressions(path)


def test_duplicate_suppression_ids_fail_clearly(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        """
        {
          "suppressions": [
            {"id": "SUP-001", "rule_id": "HIDS-AUTH-001", "reason": "Synthetic reason"},
            {"id": "SUP-001", "rule_id": "HIDS-LAB-001", "reason": "Synthetic reason"}
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unique"):
        load_suppressions(path)
