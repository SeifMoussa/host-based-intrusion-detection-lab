"""Tests for documentation consistency around CI and safety claims."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docs_check_script_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check-docs.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "docs-check: passed" in result.stdout


def test_docs_are_honest_about_unverified_github_workflows() -> None:
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ROOT / "README.md",
            ROOT / "docs" / "TESTING_GUIDE.md",
            ROOT / "docs" / "RELEASE_CHECKLIST.md",
        ]
    ).lower()

    assert "ci/codeql configured but not yet github-verified" in text
    assert "github actions passed" not in text
    assert "codeql passed" not in text
