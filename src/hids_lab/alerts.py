"""Normalized alert model for synthetic host-event detections."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


@dataclass(frozen=True)
class Alert:
    """Normalized alert emitted by a detection rule."""

    alert_id: str
    timestamp: str
    severity: str
    category: str
    rule_id: str
    title: str
    description: str
    evidence: str
    recommended_action: str
    source: str
    status: str = "open"
    tags: list[str] = field(default_factory=list)
    synthetic: bool = True

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable alert dictionary."""
        return asdict(self)


def fim_finding_to_alert(finding: dict[str, Any], *, timestamp: str | None = None) -> Alert:
    """Convert a FIM finding to the normalized alert shape."""
    status = str(finding["status"])
    severity = fim_status_to_severity(status)
    relative_path = str(finding["relative_path"])
    evidence = (
        f"status={status}; path={relative_path}; "
        f"old_hash={finding.get('old_hash')}; new_hash={finding.get('new_hash')}"
    )
    return Alert(
        alert_id=f"HIDS-FIM-{status.upper()}-{stable_alert_suffix(relative_path, status)}",
        timestamp=timestamp or datetime.now(UTC).replace(microsecond=0).isoformat(),
        severity=severity,
        category="baseline_activity",
        rule_id=f"HIDS-FIM-{status.upper()}",
        title=f"File integrity {status}",
        description=str(finding["explanation"]),
        evidence=evidence,
        recommended_action=f"Review the synthetic FIM finding for {relative_path}.",
        source="synthetic-file-integrity-monitor",
        tags=["synthetic", "fim", status],
    )


def fim_status_to_severity(status: str) -> str:
    """Map a FIM finding status to report severity."""
    if status == "unchanged":
        return "low"
    if status in {"modified", "deleted"}:
        return "high"
    if status == "added":
        return "medium"
    msg = f"Unsupported FIM status: {status}"
    raise ValueError(msg)


def stable_alert_suffix(*parts: str) -> str:
    """Create a stable suffix from safe synthetic values."""
    return sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
