"""Explicit alert suppression helpers for synthetic false-positive handling."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hids_lab.alerts import Alert

REQUIRED_SUPPRESSION_FIELDS = frozenset({"id", "rule_id", "reason"})


@dataclass(frozen=True)
class Suppression:
    """Explicit suppression rule for expected synthetic alerts."""

    id: str
    rule_id: str
    reason: str
    source_contains: str | None = None
    evidence_contains: str | None = None


def load_suppressions(path: Path) -> list[Suppression]:
    """Load and validate explicit alert suppressions."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"Invalid suppression JSON: {path}"
        raise ValueError(msg) from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("suppressions"), list):
        msg = "Suppression file must contain a suppressions list."
        raise ValueError(msg)

    suppressions = [
        parse_suppression(item, index) for index, item in enumerate(payload["suppressions"])
    ]
    suppression_ids = [suppression.id for suppression in suppressions]
    if len(suppression_ids) != len(set(suppression_ids)):
        msg = "Suppression IDs must be unique."
        raise ValueError(msg)
    return suppressions


def parse_suppression(payload: Any, index: int) -> Suppression:
    """Parse one suppression entry."""
    if not isinstance(payload, dict):
        msg = f"Suppression at index {index} must be an object."
        raise ValueError(msg)

    missing = REQUIRED_SUPPRESSION_FIELDS.difference(payload)
    if missing:
        missing_fields = ", ".join(sorted(missing))
        msg = f"Suppression at index {index} is missing fields: {missing_fields}"
        raise ValueError(msg)

    for field in REQUIRED_SUPPRESSION_FIELDS:
        if not isinstance(payload[field], str) or not payload[field].strip():
            msg = f"Suppression at index {index} has invalid field: {field}"
            raise ValueError(msg)

    return Suppression(
        id=payload["id"],
        rule_id=payload["rule_id"],
        reason=payload["reason"],
        source_contains=optional_text(payload.get("source_contains"), "source_contains", index),
        evidence_contains=optional_text(
            payload.get("evidence_contains"),
            "evidence_contains",
            index,
        ),
    )


def optional_text(value: Any, field: str, index: int) -> str | None:
    """Validate optional text suppression fields."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        msg = f"Suppression at index {index} has invalid field: {field}"
        raise ValueError(msg)
    return value


def apply_suppressions(
    alerts: list[Alert],
    suppressions: list[Suppression],
    *,
    include_suppressed: bool = False,
) -> list[dict[str, object]]:
    """Apply suppressions while preserving alert evidence and metadata."""
    output: list[dict[str, object]] = []
    for alert in alerts:
        alert_payload = alert.to_dict()
        suppression = first_matching_suppression(alert, suppressions)
        if suppression is None:
            alert_payload["suppressed"] = False
            alert_payload["suppression_id"] = None
            alert_payload["suppression_reason"] = None
            output.append(alert_payload)
            continue

        alert_payload["suppressed"] = True
        alert_payload["suppression_id"] = suppression.id
        alert_payload["suppression_reason"] = suppression.reason
        if include_suppressed:
            output.append(alert_payload)
    return output


def first_matching_suppression(
    alert: Alert,
    suppressions: list[Suppression],
) -> Suppression | None:
    """Return the first suppression matching an alert."""
    for suppression in suppressions:
        if is_suppressed(alert, suppression):
            return suppression
    return None


def is_suppressed(alert: Alert, suppression: Suppression) -> bool:
    """Return whether an alert matches one suppression rule."""
    if alert.rule_id != suppression.rule_id:
        return False
    if suppression.source_contains and suppression.source_contains not in alert.source:
        return False
    if suppression.evidence_contains and suppression.evidence_contains not in alert.evidence:
        return False
    return True


def count_suppressed(alert_payloads: list[dict[str, object]]) -> dict[str, int]:
    """Count suppressed and visible alert payloads."""
    suppressed = sum(1 for alert in alert_payloads if alert.get("suppressed") is True)
    return {
        "suppressed": suppressed,
        "unsuppressed": len(alert_payloads) - suppressed,
    }
