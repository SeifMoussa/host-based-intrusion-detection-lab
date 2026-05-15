"""Safety tests for Phase 2 synthetic data."""

from __future__ import annotations

import json
from pathlib import Path

from hids_lab.baseline import load_baseline
from hids_lab.detections import load_default_rules
from hids_lab.events import load_csv_events
from hids_lab.safety import (
    find_forbidden_terms,
    find_public_ipv4_addresses,
    find_unreserved_domains,
    path_is_inside,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
HOST_EVENTS = SAMPLES / "host_events"
SAMPLE_FILES = SAMPLES / "files"
BASELINE_PATH = ROOT / "baselines" / "example_baseline.json"
REPORT_EXAMPLES = ROOT / "reports" / "examples"


def test_sample_events_are_marked_synthetic() -> None:
    for path in HOST_EVENTS.glob("*.json"):
        if path.name == "malformed_events.json":
            continue
        events = json.loads(path.read_text(encoding="utf-8"))
        assert all(event["lab_marker"] == "synthetic-hids-lab" for event in events)
        assert all(event["host"].startswith("lab-host-") for event in events)


def test_sample_content_has_no_forbidden_terms_public_ips_or_unreserved_domains() -> None:
    checked_roots = [SAMPLES, ROOT / "suppressions"]
    for checked_root in checked_roots:
        for path in checked_root.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                assert find_forbidden_terms(text) == set()
                assert find_public_ipv4_addresses(text) == set()
                assert find_unreserved_domains(text) == set()


def test_report_examples_include_safety_disclaimer() -> None:
    for path in REPORT_EXAMPLES.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "Defensive lab-only report generated from synthetic local sample data" in text
            assert find_public_ipv4_addresses(text) == set()
            assert find_unreserved_domains(text) == set()


def test_sample_users_are_generic_lab_users() -> None:
    allowed_users = {"lab_user", "analyst_user", "service_user"}
    for path in [HOST_EVENTS / "clean_events.json", HOST_EVENTS / "suspicious_events.json"]:
        events = json.loads(path.read_text(encoding="utf-8"))
        assert {event["user"] for event in events}.issubset(allowed_users)
    assert {event["user"] for event in load_csv_events(HOST_EVENTS / "mixed_events.csv")}.issubset(
        allowed_users
    )


def test_sample_event_paths_stay_inside_samples() -> None:
    paths = []
    paths.extend(json.loads((HOST_EVENTS / "clean_events.json").read_text(encoding="utf-8")))
    paths.extend(json.loads((HOST_EVENTS / "suspicious_events.json").read_text(encoding="utf-8")))
    paths.extend(load_csv_events(HOST_EVENTS / "mixed_events.csv"))

    for event in paths:
        event_path = ROOT / event["file_path"]
        assert path_is_inside(event_path, SAMPLES)


def test_no_binary_sample_files() -> None:
    for path in SAMPLE_FILES.rglob("*"):
        if path.is_file():
            path.read_text(encoding="utf-8")


def test_baseline_references_only_repo_controlled_sample_paths() -> None:
    baseline = load_baseline(BASELINE_PATH)
    root_path = ROOT / baseline["root_path"]

    assert path_is_inside(root_path, SAMPLES)

    for entry in baseline["files"]:
        referenced_path = ROOT / entry["relative_path"]
        assert path_is_inside(referenced_path, SAMPLES)
        assert referenced_path.exists()


def test_detection_rules_use_only_synthetic_fake_markers() -> None:
    for rule in load_default_rules():
        combined = " ".join(
            [
                rule.rule_id,
                rule.name,
                rule.description,
                rule.pattern,
                rule.explanation,
                rule.recommended_action,
                " ".join(rule.tags),
            ]
        )
        assert "synthetic" in combined.lower() or "lab" in combined.lower()
        assert find_public_ipv4_addresses(combined) == set()
        assert find_unreserved_domains(combined) == set()


def test_detection_rules_avoid_unsafe_language() -> None:
    blocked_terms = {
        "credential",
        "destructive",
        "exploit",
        "malware",
        "persistence",
        "privilege escalation",
        "remediation",
        "token",
    }
    for rule in load_default_rules():
        combined = " ".join(
            [
                rule.name,
                rule.description,
                rule.explanation,
                rule.recommended_action,
                rule.pattern,
            ]
        ).lower()
        assert blocked_terms.isdisjoint(combined)


def test_source_has_no_live_os_or_process_collection_logic() -> None:
    source_text = " ".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "src").rglob("*.py")
    )

    blocked_snippets = {
        "psutil.process_iter",
        "subprocess.run",
        "wmic process",
        "get-process",
        "os.listdir('/proc'",
        "while true",
    }
    lowered = source_text.lower()
    assert all(snippet not in lowered for snippet in blocked_snippets)
