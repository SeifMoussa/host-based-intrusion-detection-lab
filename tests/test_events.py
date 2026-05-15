"""Tests for synthetic host-event sample loading."""

from pathlib import Path

import pytest

from hids_lab.events import (
    REQUIRED_EVENT_FIELDS,
    load_csv_events,
    load_json_events,
    validate_events,
)

ROOT = Path(__file__).resolve().parents[1]
HOST_EVENTS = ROOT / "samples" / "host_events"


def test_load_valid_json_host_events() -> None:
    events = load_json_events(HOST_EVENTS / "clean_events.json")

    assert len(events) == 2
    assert REQUIRED_EVENT_FIELDS.issubset(events[0])


def test_load_valid_csv_host_events() -> None:
    events = load_csv_events(HOST_EVENTS / "mixed_events.csv")

    assert len(events) == 4
    assert REQUIRED_EVENT_FIELDS.issubset(events[0])


def test_rejects_malformed_json_event_data() -> None:
    with pytest.raises(ValueError, match="missing required fields"):
        load_json_events(HOST_EVENTS / "malformed_events.json")


def test_validates_required_event_fields() -> None:
    with pytest.raises(ValueError, match="missing required fields"):
        validate_events([{"timestamp": "2026-01-15T10:00:00Z"}])
