"""Transparent detection rules for synthetic host-event records."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from hids_lab.alerts import Alert

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
VALID_CATEGORIES = frozenset(
    {"process_activity", "file_activity", "auth_activity", "baseline_activity"}
)
VALID_MATCH_TYPES = frozenset({"contains", "equals", "regex", "count_gte"})


@dataclass(frozen=True)
class DetectionRule:
    """Simple transparent rule definition for synthetic events."""

    rule_id: str
    name: str
    description: str
    severity: str
    category: str
    event_type: str | tuple[str, ...]
    field: str
    match_type: str
    pattern: str
    explanation: str
    recommended_action: str
    tags: tuple[str, ...] = ()
    enabled: bool = True
    threshold: int | None = None


def load_default_rules() -> list[DetectionRule]:
    """Return the built-in synthetic host-event rules."""
    return [
        DetectionRule(
            rule_id="HIDS-PROC-001",
            name="Synthetic suspicious command marker",
            description="Matches lab command lines that intentionally include simulate markers.",
            severity="medium",
            category="process_activity",
            event_type=("process_start", "file_create"),
            field="command_line",
            match_type="contains",
            pattern="--simulate-",
            explanation="Synthetic command line contains a lab suspicious marker.",
            recommended_action=(
                "Review the synthetic event context and confirm it is expected lab data."
            ),
            tags=("synthetic", "command_line", "lab"),
        ),
        DetectionRule(
            rule_id="HIDS-PROC-002",
            name="Synthetic scheduler parent relationship",
            description="Matches fake process records started by the lab scheduler.",
            severity="low",
            category="process_activity",
            event_type="process_start",
            field="parent_process",
            match_type="regex",
            pattern=r"^lab-scheduler$",
            explanation="Synthetic process event has a lab scheduler parent marker.",
            recommended_action=(
                "Check whether the synthetic scheduled activity is part of the exercise."
            ),
            tags=("synthetic", "parent_process", "lab"),
        ),
        DetectionRule(
            rule_id="HIDS-FILE-001",
            name="Synthetic config modification event",
            description="Matches fake write events against modified lab config samples.",
            severity="high",
            category="file_activity",
            event_type="file_write",
            field="file_path",
            match_type="contains",
            pattern="samples/files/modified/app_settings.json",
            explanation="Synthetic file write targets a modified lab config sample.",
            recommended_action=(
                "Compare the file with the approved lab baseline and document the change."
            ),
            tags=("synthetic", "file", "config"),
        ),
        DetectionRule(
            rule_id="HIDS-AUTH-001",
            name="Repeated synthetic login failures",
            description="Matches repeated fake auth failure events for the same lab user.",
            severity="medium",
            category="auth_activity",
            event_type="auth_failure",
            field="user",
            match_type="count_gte",
            pattern="lab_user",
            explanation="Multiple synthetic auth failure records were observed for a lab user.",
            recommended_action=(
                "Review the fake auth events and record the training scenario outcome."
            ),
            tags=("synthetic", "auth", "lab"),
            threshold=2,
        ),
        DetectionRule(
            rule_id="HIDS-LAB-001",
            name="Known lab suspicious marker",
            description="Matches events intentionally labeled suspicious in lab samples.",
            severity="low",
            category="process_activity",
            event_type=("process_start", "file_write", "file_create", "auth_failure"),
            field="synthetic_label",
            match_type="equals",
            pattern="suspicious",
            explanation="Event is explicitly labeled as suspicious synthetic lab data.",
            recommended_action=(
                "Use the event for triage practice; no system changes are performed."
            ),
            tags=("synthetic", "label", "lab"),
        ),
    ]


def validate_rule(rule: DetectionRule) -> None:
    """Validate one detection rule definition."""
    if not rule.rule_id or not rule.name:
        msg = "Detection rule must include rule_id and name."
        raise ValueError(msg)
    if rule.severity not in VALID_SEVERITIES:
        msg = f"Invalid severity for {rule.rule_id}: {rule.severity}"
        raise ValueError(msg)
    if rule.category not in VALID_CATEGORIES:
        msg = f"Invalid category for {rule.rule_id}: {rule.category}"
        raise ValueError(msg)
    if rule.match_type not in VALID_MATCH_TYPES:
        msg = f"Invalid match_type for {rule.rule_id}: {rule.match_type}"
        raise ValueError(msg)
    if rule.match_type == "count_gte" and (rule.threshold is None or rule.threshold < 1):
        msg = f"count_gte rule requires a positive threshold: {rule.rule_id}"
        raise ValueError(msg)


def validate_rules(rules: list[DetectionRule]) -> None:
    """Validate a rule collection and require unique rule IDs."""
    seen: set[str] = set()
    for rule in rules:
        validate_rule(rule)
        if rule.rule_id in seen:
            msg = f"Duplicate rule_id: {rule.rule_id}"
            raise ValueError(msg)
        seen.add(rule.rule_id)


def detect_event(event: dict[str, Any], rules: list[DetectionRule]) -> list[Alert]:
    """Detect per-event rules against one synthetic event."""
    validate_rules(rules)
    alerts = []
    for rule in rules:
        if not rule.enabled or rule.match_type == "count_gte":
            continue
        if event_type_matches(event, rule) and field_matches(event, rule):
            alerts.append(build_alert(event, rule))
    return alerts


def detect_events(
    events: list[dict[str, Any]], rules: list[DetectionRule] | None = None
) -> list[Alert]:
    """Detect matching rules across synthetic events."""
    rules = rules or load_default_rules()
    validate_rules(rules)
    alerts: list[Alert] = []
    for event in events:
        alerts.extend(detect_event(event, rules))
    alerts.extend(detect_count_rules(events, rules))
    return alerts


def summarize_alerts(alerts: list[Alert]) -> dict[str, Any]:
    """Summarize alerts by severity and category."""
    return {
        "total": len(alerts),
        "by_severity": dict(Counter(alert.severity for alert in alerts)),
        "by_category": dict(Counter(alert.category for alert in alerts)),
    }


def event_type_matches(event: dict[str, Any], rule: DetectionRule) -> bool:
    """Return whether an event type matches a rule."""
    event_type = event.get("event_type", "")
    if isinstance(rule.event_type, tuple):
        return event_type in rule.event_type
    return event_type == rule.event_type


def field_matches(event: dict[str, Any], rule: DetectionRule) -> bool:
    """Return whether a rule matches an event field."""
    value = str(event.get(rule.field, ""))
    if rule.match_type == "contains":
        return rule.pattern in value
    if rule.match_type == "equals":
        return value == rule.pattern
    if rule.match_type == "regex":
        return re.search(rule.pattern, value) is not None
    if rule.match_type == "count_gte":
        return False
    msg = f"Unsupported match_type: {rule.match_type}"
    raise ValueError(msg)


def detect_count_rules(events: list[dict[str, Any]], rules: list[DetectionRule]) -> list[Alert]:
    """Detect count_gte rules across a batch of events."""
    alerts: list[Alert] = []
    for rule in rules:
        if not rule.enabled or rule.match_type != "count_gte":
            continue
        matching_events = [
            event
            for event in events
            if event_type_matches(event, rule) and str(event.get(rule.field, "")) == rule.pattern
        ]
        if len(matching_events) >= (rule.threshold or 1):
            evidence = f"{rule.field}={rule.pattern}; count={len(matching_events)}"
            alerts.append(build_alert(matching_events[-1], rule, evidence=evidence))
    return alerts


def build_alert(
    event: dict[str, Any], rule: DetectionRule, *, evidence: str | None = None
) -> Alert:
    """Build a normalized alert for a matching synthetic event."""
    evidence_text = evidence or f"{rule.field}={str(event.get(rule.field, ''))[:120]}"
    return Alert(
        alert_id=f"{rule.rule_id}-{stable_event_suffix(event)}",
        timestamp=str(event.get("timestamp", "")),
        severity=rule.severity,
        category=rule.category,
        rule_id=rule.rule_id,
        title=rule.name,
        description=rule.description,
        evidence=evidence_text,
        recommended_action=rule.recommended_action,
        source=str(event.get("host", "synthetic-host-event")),
        tags=list(rule.tags),
    )


def stable_event_suffix(event: dict[str, Any]) -> str:
    """Create a stable short suffix from safe synthetic event fields."""
    pieces = [
        str(event.get("timestamp", "")),
        str(event.get("host", "")),
        str(event.get("event_type", "")),
        str(event.get("process_name", "")),
    ]
    digest = sha256("|".join(pieces).encode("utf-8")).hexdigest()
    return digest[:12]
