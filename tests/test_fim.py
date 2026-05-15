"""Tests for Phase 3 file integrity monitoring behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hids_lab.baseline import calculate_sha256, create_baseline, validate_scan_root
from hids_lab.fim import compare_to_baseline

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CLEAN = ROOT / "samples" / "files" / "clean"


def test_sha256_calculation(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("abc", encoding="utf-8")

    assert calculate_sha256(sample) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_baseline_generation_from_clean_samples() -> None:
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT)

    assert baseline["baseline_version"] == "1.0"
    assert baseline["root_path"] == "samples/files/clean"
    assert {entry["relative_path"] for entry in baseline["files"]} == {
        "samples/files/clean/app_settings.json",
        "samples/files/clean/config.txt",
        "samples/files/clean/notes.txt",
    }


def test_baseline_entries_use_relative_paths() -> None:
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT)

    for entry in baseline["files"]:
        path = Path(entry["relative_path"])
        assert not path.is_absolute()
        assert ".." not in path.parts


def test_unchanged_files_detected() -> None:
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT)

    findings = compare_to_baseline(baseline, SAMPLE_CLEAN, repo_root=ROOT)

    assert {finding["status"] for finding in findings} == {"unchanged"}


def test_modified_added_and_deleted_files_detected(tmp_path: Path) -> None:
    repo_root = tmp_path
    allowed_base = repo_root / "samples"
    baseline_root = allowed_base / "files" / "baseline"
    current_root = allowed_base / "files" / "current"
    baseline_root.mkdir(parents=True)
    current_root.mkdir(parents=True)

    (baseline_root / "unchanged.txt").write_text("same", encoding="utf-8")
    (baseline_root / "modified.txt").write_text("old", encoding="utf-8")
    (baseline_root / "deleted.txt").write_text("gone", encoding="utf-8")

    (current_root / "unchanged.txt").write_text("same", encoding="utf-8")
    (current_root / "modified.txt").write_text("new", encoding="utf-8")
    (current_root / "added.txt").write_text("added", encoding="utf-8")

    baseline = create_baseline(
        baseline_root,
        repo_root=repo_root,
        allowed_base=allowed_base,
        generated_at="2026-01-15T10:00:00Z",
    )
    findings = compare_to_baseline(
        baseline,
        current_root,
        repo_root=repo_root,
        allowed_base=allowed_base,
    )

    by_path = {finding["relative_path"]: finding for finding in findings}
    assert by_path["unchanged.txt"]["status"] == "unchanged"
    assert by_path["modified.txt"]["status"] == "modified"
    assert by_path["added.txt"]["status"] == "added"
    assert by_path["deleted.txt"]["status"] == "deleted"


def test_comparison_does_not_mutate_files(tmp_path: Path) -> None:
    repo_root = tmp_path
    allowed_base = repo_root / "samples"
    root = allowed_base / "files" / "clean"
    root.mkdir(parents=True)
    sample = root / "config.txt"
    sample.write_text("stable", encoding="utf-8")
    before = sample.read_text(encoding="utf-8")

    baseline = create_baseline(root, repo_root=repo_root, allowed_base=allowed_base)
    compare_to_baseline(baseline, root, repo_root=repo_root, allowed_base=allowed_base)

    assert sample.read_text(encoding="utf-8") == before


def test_unsafe_path_traversal_rejected() -> None:
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT)
    baseline["files"][0]["relative_path"] = "../outside.txt"

    with pytest.raises(ValueError, match="traversal"):
        compare_to_baseline(baseline, SAMPLE_CLEAN, repo_root=ROOT)


def test_nonexistent_root_rejected() -> None:
    with pytest.raises(ValueError, match="does not exist"):
        validate_scan_root(
            ROOT / "samples" / "files" / "missing",
            repo_root=ROOT,
            allowed_base=ROOT / "samples",
        )


def test_root_outside_samples_rejected() -> None:
    with pytest.raises(ValueError, match="allowed sample area"):
        validate_scan_root(ROOT, repo_root=ROOT, allowed_base=ROOT / "samples")


def test_baseline_json_shape() -> None:
    baseline = create_baseline(SAMPLE_CLEAN, repo_root=ROOT)
    encoded = json.dumps(baseline)

    assert "baseline_version" in encoded
    assert "files" in encoded
