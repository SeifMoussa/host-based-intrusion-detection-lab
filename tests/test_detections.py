"""Tests for synthetic host-event detection rules."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from hids_lab.alerts import Alert
from hids_lab.detections import (
    VALID_SEVERITIES,
    DetectionRule,
    detect_event,
    detect_events,
    load_default_rules,
    validate_rules,
)
from hids_lab.events import load_csv_events, load_json_events

ROOT = Path(__file__).resolve().parents[1]
HOST_EVENTS = ROOT / "samples" / "host_events"


def test_default_rules_load_correctly() -> None:
    rules = load_default_rules()

    assert len(rules) >= 5
    validate_rules(rules)


def test_rule_ids_are_unique() -> None:
    rules = load_default_rules()
    rule_ids = [rule.rule_id for rule in rules]

    assert len(rule_ids) == len(set(rule_ids))


def test_severity_values_are_valid() -> None:
    for rule in load_default_rules():
        assert rule.severity in VALID_SEVERITIES


def test_contains_matching() -> None:
    event = load_json_events(HOST_EVENTS / "suspicious_events.json")[0]
    rule = next(rule for rule in load_default_rules() if rule.rule_id == "HIDS-PROC-001")

    alerts = detect_event(event, [rule])

    assert alerts
    assert alerts[0].rule_id == "HIDS-PROC-001"


def test_equals_matching() -> None:
    event = load_json_events(HOST_EVENTS / "suspicious_events.json")[0]
    rule = next(rule for rule in load_default_rules() if rule.rule_id == "HIDS-LAB-001")

    alerts = detect_event(event, [rule])

    assert alerts
    assert alerts[0].rule_id == "HIDS-LAB-001"


def test_regex_matching() -> None:
    event = load_json_events(HOST_EVENTS / "suspicious_events.json")[0]
    rule = next(rule for rule in load_default_rules() if rule.rule_id == "HIDS-PROC-002")

    alerts = detect_event(event, [rule])

    assert alerts
    assert alerts[0].rule_id == "HIDS-PROC-002"


def test_disabled_rules_are_skipped() -> None:
    event = load_json_events(HOST_EVENTS / "suspicious_events.json")[0]
    rule = replace(
        next(rule for rule in load_default_rules() if rule.rule_id == "HIDS-PROC-001"),
        enabled=False,
    )

    assert detect_event(event, [rule]) == []


def test_clean_events_produce_no_high_or_critical_alerts() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "clean_events.json"))

    assert all(alert.severity not in {"high", "critical"} for alert in alerts)


def test_suspicious_events_produce_expected_alerts() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    rule_ids = {alert.rule_id for alert in alerts}

    assert "HIDS-PROC-001" in rule_ids
    assert "HIDS-PROC-002" in rule_ids
    assert "HIDS-FILE-001" in rule_ids
    assert "HIDS-AUTH-001" in rule_ids
    assert "HIDS-LAB-001" in rule_ids


def test_mixed_csv_events_produce_expected_alerts() -> None:
    alerts = detect_events(load_csv_events(HOST_EVENTS / "mixed_events.csv"))
    rule_ids = {alert.rule_id for alert in alerts}

    assert "HIDS-PROC-001" in rule_ids
    assert "HIDS-AUTH-001" in rule_ids
    assert "HIDS-LAB-001" in rule_ids


def test_invalid_rule_definition_fails_safely() -> None:
    rule = DetectionRule(
        rule_id="BAD",
        name="Bad rule",
        description="Invalid test rule.",
        severity="urgent",
        category="process_activity",
        event_type="process_start",
        field="command_line",
        match_type="contains",
        pattern="synthetic",
        explanation="Invalid rule for testing.",
        recommended_action="Fix the test rule.",
    )

    with pytest.raises(ValueError, match="Invalid severity"):
        validate_rules([rule])


def test_alert_fields_include_triage_context() -> None:
    alerts = detect_events(load_json_events(HOST_EVENTS / "suspicious_events.json"))
    alert = alerts[0]

    assert isinstance(alert, Alert)
    assert alert.severity
    assert alert.evidence
    assert alert.recommended_action
    assert alert.status == "open"
    assert alert.synthetic is True
