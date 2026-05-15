"""File integrity monitoring comparison logic for safe sample paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hids_lab.baseline import (
    build_baseline_entry,
    iter_regular_files,
    validate_baseline,
    validate_baseline_paths,
    validate_scan_root,
)

FIM_STATUSES = frozenset({"unchanged", "modified", "added", "deleted"})


def compare_to_baseline(
    baseline: dict[str, Any],
    root: Path,
    *,
    repo_root: Path | None = None,
    allowed_base: Path | None = None,
) -> list[dict[str, Any]]:
    """Compare a saved baseline to the current state of an explicit safe directory."""
    repo_root = (repo_root or Path.cwd()).resolve()
    allowed_base = (allowed_base or repo_root / "samples").resolve()

    validate_baseline(baseline)
    validate_baseline_paths(baseline, repo_root=repo_root, allowed_base=allowed_base)
    safe_root = validate_scan_root(root, repo_root=repo_root, allowed_base=allowed_base)

    baseline_root = (repo_root / baseline["root_path"]).resolve()
    baseline_entries = {
        root_relative_key(
            entry["relative_path"],
            baseline_root=baseline_root,
            repo_root=repo_root,
        ): entry
        for entry in baseline["files"]
    }
    current_entries = {
        path.relative_to(safe_root).as_posix(): build_baseline_entry(
            path,
            repo_root=repo_root,
        )
        for path in iter_regular_files(safe_root, allowed_base=allowed_base)
    }

    findings: list[dict[str, Any]] = []
    for relative_path in sorted(baseline_entries.keys() | current_entries.keys()):
        old_entry = baseline_entries.get(relative_path)
        new_entry = current_entries.get(relative_path)
        findings.append(build_finding(relative_path, old_entry=old_entry, new_entry=new_entry))

    return findings


def build_finding(
    relative_path: str,
    *,
    old_entry: dict[str, Any] | None,
    new_entry: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build one FIM finding from old and current file metadata."""
    if old_entry is None and new_entry is not None:
        return {
            "relative_path": relative_path,
            "status": "added",
            "old_hash": None,
            "new_hash": new_entry["sha256"],
            "old_size": None,
            "new_size": new_entry["size_bytes"],
            "explanation": "File exists in the current scan but not in the baseline.",
        }

    if old_entry is not None and new_entry is None:
        return {
            "relative_path": relative_path,
            "status": "deleted",
            "old_hash": old_entry["sha256"],
            "new_hash": None,
            "old_size": old_entry["size_bytes"],
            "new_size": None,
            "explanation": "File exists in the baseline but not in the current scan.",
        }

    if old_entry is None or new_entry is None:
        msg = "Invalid FIM comparison state."
        raise ValueError(msg)

    if (
        old_entry["sha256"] == new_entry["sha256"]
        and old_entry["size_bytes"] == new_entry["size_bytes"]
    ):
        return {
            "relative_path": relative_path,
            "status": "unchanged",
            "old_hash": old_entry["sha256"],
            "new_hash": new_entry["sha256"],
            "old_size": old_entry["size_bytes"],
            "new_size": new_entry["size_bytes"],
            "explanation": "File matches the baseline hash and size.",
        }

    return {
        "relative_path": relative_path,
        "status": "modified",
        "old_hash": old_entry["sha256"],
        "new_hash": new_entry["sha256"],
        "old_size": old_entry["size_bytes"],
        "new_size": new_entry["size_bytes"],
        "explanation": "File hash or size differs from the baseline.",
    }


def root_relative_key(relative_path: str, *, baseline_root: Path, repo_root: Path) -> str:
    """Convert a baseline repo-relative path to a baseline-root-relative key."""
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts:
        msg = f"Baseline path may not be absolute or use traversal: {relative_path}"
        raise ValueError(msg)

    full_path = (repo_root / path).resolve()
    try:
        return full_path.relative_to(baseline_root).as_posix()
    except ValueError:
        return path.as_posix()
