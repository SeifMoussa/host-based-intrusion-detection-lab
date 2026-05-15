"""Synthetic host-event sample loading and shape validation."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hids_lab.safety import path_is_inside

REQUIRED_EVENT_FIELDS = frozenset(
    {
        "timestamp",
        "host",
        "event_type",
        "process_name",
        "command_line",
        "user",
        "parent_process",
        "file_path",
        "action",
        "synthetic_label",
        "lab_marker",
    }
)


@dataclass(frozen=True)
class HostEvent:
    """Expected shape for a synthetic host-event record."""

    timestamp: str
    host: str
    event_type: str
    process_name: str
    command_line: str
    user: str
    parent_process: str
    file_path: str
    action: str
    synthetic_label: str
    lab_marker: str


def load_json_events(path: Path) -> list[dict[str, Any]]:
    """Load a JSON event sample and validate its basic shape."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"Invalid JSON event sample: {path}"
        raise ValueError(msg) from exc

    if not isinstance(payload, list):
        msg = "JSON event sample must contain a list of event objects."
        raise ValueError(msg)

    events = _ensure_dict_records(payload)
    validate_events(events)
    return events


def load_csv_events(path: Path) -> list[dict[str, str]]:
    """Load a CSV event sample and validate its basic shape."""
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        events = list(reader)

    validate_events(events)
    return events


def load_events_file(path: Path) -> list[dict[str, Any]]:
    """Load JSON or CSV synthetic host events based on file extension."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        return load_json_events(path)
    if suffix == ".csv":
        return load_csv_events(path)
    msg = f"Unsupported event sample format: {path.suffix}"
    raise ValueError(msg)


def validate_event_input_path(
    path: Path,
    *,
    repo_root: Path | None = None,
    allowed_base: Path | None = None,
) -> Path:
    """Validate that an event input is an explicit sample file."""
    repo_root = (repo_root or Path.cwd()).resolve()
    allowed_base = (allowed_base or repo_root / "samples" / "host_events").resolve()
    candidate = path if path.is_absolute() else repo_root / path
    resolved = candidate.resolve()

    if not resolved.exists():
        msg = f"Event input does not exist: {path}"
        raise ValueError(msg)
    if not resolved.is_file():
        msg = f"Event input is not a file: {path}"
        raise ValueError(msg)
    if not path_is_inside(resolved, allowed_base):
        msg = f"Event input must be inside the synthetic host-event sample area: {allowed_base}"
        raise ValueError(msg)
    return resolved


def validate_events(events: list[dict[str, Any]]) -> None:
    """Validate required synthetic event fields."""
    for index, event in enumerate(events):
        missing = REQUIRED_EVENT_FIELDS.difference(event)
        if missing:
            missing_fields = ", ".join(sorted(missing))
            msg = f"Event at index {index} is missing required fields: {missing_fields}"
            raise ValueError(msg)

        for field in REQUIRED_EVENT_FIELDS:
            value = event[field]
            if not isinstance(value, str) or not value.strip():
                msg = f"Event at index {index} has an invalid value for field: {field}"
                raise ValueError(msg)


def _ensure_dict_records(payload: list[Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            msg = f"Event at index {index} must be an object."
            raise ValueError(msg)
        events.append(item)
    return events
