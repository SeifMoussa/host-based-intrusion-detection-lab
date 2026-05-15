"""Meaningful coverage for validation and error edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from hids_lab.alerts import fim_finding_to_alert
from hids_lab.baseline import (
    create_baseline,
    iter_regular_files,
    validate_baseline,
    validate_baseline_file_entry,
    validate_baseline_paths,
    validate_scan_root,
)
from hids_lab.detections import DetectionRule, detect_events, field_matches, validate_rules
from hids_lab.events import load_json_events, validate_event_input_path, validate_events
from hids_lab.fim import build_finding, root_relative_key
from hids_lab.safety import find_public_ipv4_addresses, path_is_inside
from hids_lab.suppressions import Suppression, is_suppressed, load_suppressions

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_validate_baseline_rejects_non_object_and_bad_files_field() -> None:
    with pytest.raises(ValueError, match="must be a JSON object"):
        validate_baseline([])

    with pytest.raises(ValueError, match="files field must be a list"):
        validate_baseline(
            {
                "baseline_version": "1.0",
                "generated_at": "2026-01-15T00:00:00Z",
                "root_path": "samples/files/clean",
                "files": {},
            }
        )


def test_validate_baseline_rejects_blank_metadata_and_bad_entries() -> None:
    with pytest.raises(ValueError, match="invalid value"):
        validate_baseline(
            {
                "baseline_version": "",
                "generated_at": "2026-01-15T00:00:00Z",
                "root_path": "samples/files/clean",
                "files": [],
            }
        )

    with pytest.raises(ValueError, match="must be an object"):
        validate_baseline_file_entry("bad")

    with pytest.raises(ValueError, match="invalid relative_path"):
        validate_baseline_file_entry(
            {
                "relative_path": "",
                "sha256": "a" * 64,
                "size_bytes": 1,
                "modified_time_utc": "2026-01-15T00:00:00Z",
                "status": "baseline",
            }
        )

    with pytest.raises(ValueError, match="invalid size_bytes"):
        validate_baseline_file_entry(
            {
                "relative_path": "samples/files/clean/config.txt",
                "sha256": "a" * 64,
                "size_bytes": -1,
                "modified_time_utc": "2026-01-15T00:00:00Z",
                "status": "baseline",
            }
        )


def test_validate_baseline_paths_rejects_out_of_scope_root_and_file() -> None:
    baseline = create_baseline(SAMPLES / "files" / "clean", repo_root=ROOT)
    baseline["root_path"] = "docs"

    with pytest.raises(ValueError, match="root_path"):
        validate_baseline_paths(baseline, repo_root=ROOT, allowed_base=SAMPLES)

    baseline = create_baseline(SAMPLES / "files" / "clean", repo_root=ROOT)
    baseline["files"][0]["relative_path"] = "docs/SAFETY.md"

    with pytest.raises(ValueError, match="allowed sample area"):
        validate_baseline_paths(baseline, repo_root=ROOT, allowed_base=SAMPLES)


def test_scan_root_rejects_file_and_iter_skips_hidden_files(tmp_path: Path) -> None:
    repo_root = tmp_path
    allowed_base = repo_root / "samples"
    root = allowed_base / "files"
    root.mkdir(parents=True)
    visible = root / "visible.txt"
    hidden = root / ".hidden.txt"
    visible.write_text("visible", encoding="utf-8")
    hidden.write_text("hidden", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        validate_scan_root(visible, repo_root=repo_root, allowed_base=allowed_base)

    files = iter_regular_files(root, allowed_base=allowed_base)
    assert files == [visible.resolve()]


def test_event_input_path_rejects_directory_and_out_of_scope_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a file"):
        validate_event_input_path(SAMPLES / "host_events", repo_root=ROOT)

    outside = tmp_path / "events.json"
    outside.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="sample area"):
        validate_event_input_path(outside, repo_root=ROOT)


def test_event_validation_rejects_non_object_and_blank_field(tmp_path: Path) -> None:
    path = tmp_path / "events.json"
    path.write_text('["bad"]', encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        load_json_events(path)

    event = {
        "timestamp": "2026-01-15T00:00:00Z",
        "host": "lab-host-01",
        "event_type": "process_start",
        "process_name": "lab-tool",
        "command_line": "",
        "user": "lab_user",
        "parent_process": "lab-terminal",
        "file_path": "samples/files/clean/config.txt",
        "action": "read",
        "synthetic_label": "clean",
        "lab_marker": "synthetic-hids-lab",
    }
    with pytest.raises(ValueError, match="invalid value"):
        validate_events([event])


def test_detection_validation_rejects_bad_metadata_and_count_threshold() -> None:
    base = DetectionRule(
        rule_id="",
        name="",
        description="Synthetic invalid rule.",
        severity="low",
        category="process_activity",
        event_type="process_start",
        field="command_line",
        match_type="contains",
        pattern="synthetic",
        explanation="Synthetic invalid rule.",
        recommended_action="Review synthetic invalid rule.",
    )
    with pytest.raises(ValueError, match="rule_id and name"):
        validate_rules([base])

    bad_category = DetectionRule(
        rule_id="BAD",
        name="Bad",
        description="Synthetic invalid rule.",
        severity="low",
        category="bad",
        event_type="process_start",
        field="command_line",
        match_type="contains",
        pattern="synthetic",
        explanation="Synthetic invalid rule.",
        recommended_action="Review synthetic invalid rule.",
    )
    with pytest.raises(ValueError, match="Invalid category"):
        validate_rules([bad_category])

    count_rule = DetectionRule(
        rule_id="BAD-COUNT",
        name="Bad count",
        description="Synthetic invalid count rule.",
        severity="low",
        category="auth_activity",
        event_type="auth_failure",
        field="user",
        match_type="count_gte",
        pattern="lab_user",
        explanation="Synthetic invalid count rule.",
        recommended_action="Review synthetic invalid count rule.",
        threshold=0,
    )
    with pytest.raises(ValueError, match="positive threshold"):
        validate_rules([count_rule])


def test_detection_duplicate_and_unsupported_match_type_branches() -> None:
    rule = DetectionRule(
        rule_id="DUP",
        name="Duplicate",
        description="Synthetic duplicate rule.",
        severity="low",
        category="process_activity",
        event_type="process_start",
        field="command_line",
        match_type="contains",
        pattern="synthetic",
        explanation="Synthetic duplicate rule.",
        recommended_action="Review synthetic duplicate rule.",
    )
    with pytest.raises(ValueError, match="Duplicate rule_id"):
        validate_rules([rule, rule])

    object.__setattr__(rule, "match_type", "unsupported")
    with pytest.raises(ValueError, match="Unsupported match_type"):
        field_matches({"command_line": "synthetic"}, rule)


def test_detection_defaults_to_builtin_rules_when_rules_none() -> None:
    alerts = detect_events(
        [
            {
                "timestamp": "2026-01-15T00:00:00Z",
                "host": "lab-host-01",
                "event_type": "file_create",
                "process_name": "lab-script-runner",
                "command_line": "lab-script-runner --simulate-new-note",
                "user": "lab_user",
                "parent_process": "lab-terminal",
                "file_path": "samples/files/new/notes.txt",
                "action": "create",
                "synthetic_label": "suspicious",
                "lab_marker": "synthetic-hids-lab",
            }
        ],
        rules=None,
    )
    assert {alert.rule_id for alert in alerts} == {"HIDS-PROC-001", "HIDS-LAB-001"}


def test_fim_invalid_state_and_root_relative_fallback() -> None:
    with pytest.raises(ValueError, match="Invalid FIM comparison state"):
        build_finding("bad.txt", old_entry=None, new_entry=None)

    assert (
        root_relative_key(
            "samples/files/clean/config.txt",
            baseline_root=ROOT / "other",
            repo_root=ROOT,
        )
        == "samples/files/clean/config.txt"
    )


def test_fim_alert_rejects_unknown_status() -> None:
    with pytest.raises(ValueError, match="Unsupported FIM status"):
        fim_finding_to_alert(
            {
                "relative_path": "config.txt",
                "status": "unknown",
                "old_hash": None,
                "new_hash": None,
                "old_size": None,
                "new_size": None,
                "explanation": "Synthetic invalid status.",
            }
        )


def test_suppression_schema_edge_cases(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"suppressions": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="suppressions list"):
        load_suppressions(path)

    path.write_text('{"suppressions": ["bad"]}', encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        load_suppressions(path)

    path.write_text(
        '{"suppressions": [{"id": "SUP", "rule_id": "HIDS-AUTH-001", "reason": ""}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid field"):
        load_suppressions(path)

    path.write_text(
        """
        {
          "suppressions": [
            {
              "id": "SUP",
              "rule_id": "HIDS-AUTH-001",
              "reason": "Synthetic reason",
              "source_contains": ""
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid field"):
        load_suppressions(path)


def test_suppression_non_matching_source_and_evidence() -> None:
    alert = detect_events(
        [
            {
                "timestamp": "2026-01-15T00:00:00Z",
                "host": "lab-host-01",
                "event_type": "auth_failure",
                "process_name": "lab-auth-simulator",
                "command_line": "lab-auth-simulator --record-failed-login",
                "user": "lab_user",
                "parent_process": "lab-terminal",
                "file_path": "samples/files/clean/notes.txt",
                "action": "login_failed",
                "synthetic_label": "suspicious",
                "lab_marker": "synthetic-hids-lab",
            },
            {
                "timestamp": "2026-01-15T00:01:00Z",
                "host": "lab-host-01",
                "event_type": "auth_failure",
                "process_name": "lab-auth-simulator",
                "command_line": "lab-auth-simulator --record-failed-login",
                "user": "lab_user",
                "parent_process": "lab-terminal",
                "file_path": "samples/files/clean/notes.txt",
                "action": "login_failed",
                "synthetic_label": "suspicious",
                "lab_marker": "synthetic-hids-lab",
            },
        ]
    )[-1]

    assert not is_suppressed(
        alert,
        Suppression(
            id="SUP",
            rule_id=alert.rule_id,
            reason="Synthetic reason",
            source_contains="other-host",
        ),
    )
    assert not is_suppressed(
        alert,
        Suppression(
            id="SUP",
            rule_id=alert.rule_id,
            reason="Synthetic reason",
            evidence_contains="other-evidence",
        ),
    )


def test_safety_helpers_cover_invalid_ip_and_path_false_branch() -> None:
    assert find_public_ipv4_addresses("999.999.999.999") == set()
    assert not path_is_inside(ROOT / "README.md", SAMPLES)
