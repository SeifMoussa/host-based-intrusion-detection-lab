"""Tests for the Phase 2 example baseline shape."""

from pathlib import Path

import pytest

from hids_lab.baseline import load_baseline, validate_baseline, validate_baseline_file_entry

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "baselines" / "example_baseline.json"


def test_validates_baseline_shape() -> None:
    baseline = load_baseline(BASELINE_PATH)

    assert baseline["baseline_version"] == "1.0"
    assert baseline["root_path"] == "samples/files/clean"
    assert len(baseline["files"]) == 3


def test_validates_baseline_file_entries() -> None:
    baseline = load_baseline(BASELINE_PATH)

    for entry in baseline["files"]:
        validate_baseline_file_entry(entry)


def test_rejects_invalid_baseline_shape() -> None:
    with pytest.raises(ValueError, match="missing required fields"):
        validate_baseline({"baseline_version": "1.0"})


def test_rejects_invalid_file_entry_hash() -> None:
    with pytest.raises(ValueError, match="invalid sha256"):
        validate_baseline_file_entry(
            {
                "relative_path": "samples/files/clean/config.txt",
                "sha256": "short",
                "size_bytes": 10,
                "modified_time_utc": "2026-01-15T10:00:00Z",
                "status": "baseline",
            }
        )
