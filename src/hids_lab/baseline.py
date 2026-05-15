"""JSON baseline schema, shape validation, and safe baseline generation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hids_lab.safety import path_is_inside

REQUIRED_BASELINE_FIELDS = frozenset(
    {
        "baseline_version",
        "generated_at",
        "root_path",
        "files",
    }
)

REQUIRED_FILE_ENTRY_FIELDS = frozenset(
    {
        "relative_path",
        "sha256",
        "size_bytes",
        "modified_time_utc",
        "status",
    }
)

BASELINE_VERSION = "1.0"
SKIPPED_DIR_NAMES = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache"})


@dataclass(frozen=True)
class BaselineEntry:
    """Expected shape for one file entry in a JSON baseline."""

    relative_path: str
    sha256: str
    size_bytes: int
    modified_time_utc: str
    status: str


@dataclass(frozen=True)
class Baseline:
    """Expected shape for a JSON baseline document."""

    baseline_version: str
    generated_at: str
    root_path: str
    files: list[BaselineEntry]


def load_baseline(path: Path) -> dict[str, Any]:
    """Load and validate a JSON baseline sample."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"Invalid JSON baseline: {path}"
        raise ValueError(msg) from exc

    validate_baseline(payload)
    return payload


def write_baseline(baseline: dict[str, Any], output_path: Path) -> None:
    """Write a validated JSON baseline document."""
    validate_baseline(baseline)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def create_baseline(
    root: Path,
    *,
    repo_root: Path | None = None,
    allowed_base: Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create a JSON baseline for an explicit safe directory."""
    repo_root = (repo_root or Path.cwd()).resolve()
    allowed_base = (allowed_base or repo_root / "samples").resolve()
    safe_root = validate_scan_root(root, repo_root=repo_root, allowed_base=allowed_base)

    files = [
        build_baseline_entry(path, repo_root=repo_root)
        for path in iter_regular_files(safe_root, allowed_base=allowed_base)
    ]
    files.sort(key=lambda entry: entry["relative_path"])

    baseline = {
        "baseline_version": BASELINE_VERSION,
        "generated_at": generated_at or datetime.now(UTC).replace(microsecond=0).isoformat(),
        "root_path": path_to_posix(safe_root.relative_to(repo_root))
        if path_is_inside(safe_root, repo_root)
        else path_to_posix(safe_root),
        "files": files,
    }
    validate_baseline(baseline)
    return baseline


def build_baseline_entry(path: Path, *, repo_root: Path) -> dict[str, Any]:
    """Build one baseline entry for a regular file."""
    stat = path.stat()
    resolved_path = path.resolve()
    if path_is_inside(path, repo_root):
        relative_path = path_to_posix(resolved_path.relative_to(repo_root.resolve()))
    else:
        relative_path = path_to_posix(resolved_path)
    return {
        "relative_path": relative_path,
        "sha256": calculate_sha256(path),
        "size_bytes": stat.st_size,
        "modified_time_utc": datetime.fromtimestamp(stat.st_mtime, UTC)
        .replace(microsecond=0)
        .isoformat(),
        "status": "baseline",
    }


def calculate_sha256(path: Path) -> str:
    """Calculate a SHA-256 digest for a regular file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_regular_files(root: Path, *, allowed_base: Path) -> list[Path]:
    """Return regular files under root, excluding hidden/cache paths."""
    files: list[Path] = []
    for path in root.rglob("*"):
        if should_skip_path(path, root=root):
            continue
        if path.is_file() and not path.name.startswith("."):
            resolved = path.resolve()
            if not path_is_inside(resolved, allowed_base):
                msg = f"Refusing to include file outside allowed sample area: {path}"
                raise ValueError(msg)
            files.append(resolved)
    return files


def should_skip_path(path: Path, *, root: Path) -> bool:
    """Return whether a path should be skipped during sample scanning."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part.startswith(".") or part in SKIPPED_DIR_NAMES for part in parts)


def validate_scan_root(root: Path, *, repo_root: Path, allowed_base: Path) -> Path:
    """Validate an explicit scan root for safe sample-only scanning."""
    if not root:
        msg = "A root path is required."
        raise ValueError(msg)

    candidate = root if root.is_absolute() else repo_root / root
    resolved = candidate.resolve()

    if not resolved.exists():
        msg = f"Root path does not exist: {root}"
        raise ValueError(msg)

    if not resolved.is_dir():
        msg = f"Root path is not a directory: {root}"
        raise ValueError(msg)

    if not path_is_inside(resolved, allowed_base):
        msg = f"Root path must be inside the allowed sample area: {allowed_base}"
        raise ValueError(msg)

    return resolved


def validate_baseline_paths(
    baseline: dict[str, Any],
    *,
    repo_root: Path,
    allowed_base: Path,
) -> None:
    """Validate that baseline paths stay inside the allowed sample area."""
    root_path = repo_root / baseline["root_path"]
    if not path_is_inside(root_path, allowed_base):
        msg = "Baseline root_path must stay inside the allowed sample area."
        raise ValueError(msg)

    for entry in baseline["files"]:
        relative_path = Path(entry["relative_path"])
        if relative_path.is_absolute() or ".." in relative_path.parts:
            msg = f"Baseline path may not be absolute or use traversal: {entry['relative_path']}"
            raise ValueError(msg)
        full_path = repo_root / relative_path
        if not path_is_inside(full_path, allowed_base):
            msg = f"Baseline file path must stay inside the allowed sample area: {relative_path}"
            raise ValueError(msg)


def validate_baseline(payload: Any) -> None:
    """Validate required fields in a baseline document."""
    if not isinstance(payload, dict):
        msg = "Baseline must be a JSON object."
        raise ValueError(msg)

    missing = REQUIRED_BASELINE_FIELDS.difference(payload)
    if missing:
        missing_fields = ", ".join(sorted(missing))
        msg = f"Baseline is missing required fields: {missing_fields}"
        raise ValueError(msg)

    if not isinstance(payload["files"], list):
        msg = "Baseline files field must be a list."
        raise ValueError(msg)

    for field in ("baseline_version", "generated_at", "root_path"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            msg = f"Baseline field has invalid value: {field}"
            raise ValueError(msg)

    for index, file_entry in enumerate(payload["files"]):
        validate_baseline_file_entry(file_entry, index)


def validate_baseline_file_entry(file_entry: Any, index: int = 0) -> None:
    """Validate one baseline file entry."""
    if not isinstance(file_entry, dict):
        msg = f"Baseline file entry at index {index} must be an object."
        raise ValueError(msg)

    missing = REQUIRED_FILE_ENTRY_FIELDS.difference(file_entry)
    if missing:
        missing_fields = ", ".join(sorted(missing))
        msg = f"Baseline file entry at index {index} is missing fields: {missing_fields}"
        raise ValueError(msg)

    if not isinstance(file_entry["relative_path"], str) or not file_entry["relative_path"]:
        msg = f"Baseline file entry at index {index} has invalid relative_path."
        raise ValueError(msg)

    if not isinstance(file_entry["sha256"], str) or len(file_entry["sha256"]) != 64:
        msg = f"Baseline file entry at index {index} has invalid sha256."
        raise ValueError(msg)

    if not isinstance(file_entry["size_bytes"], int) or file_entry["size_bytes"] < 0:
        msg = f"Baseline file entry at index {index} has invalid size_bytes."
        raise ValueError(msg)


def path_to_posix(path: Path) -> str:
    """Convert a path to stable POSIX-style text for JSON output."""
    return path.as_posix()
