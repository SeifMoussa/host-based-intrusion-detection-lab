"""Tests for GitHub workflow and repository automation configuration."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_ci_workflow_has_required_jobs_and_python_version() -> None:
    workflow = read(".github/workflows/ci.yml")

    assert "tests:" in workflow
    assert "docs:" in workflow
    assert "cli-smoke:" in workflow
    assert 'python-version: "3.12"' in workflow
    assert "--cov-fail-under=90" in workflow
    assert "python scripts/check-docs.py" in workflow


def test_ci_workflow_has_required_triggers_and_safe_cli_commands() -> None:
    workflow = read(".github/workflows/ci.yml")

    assert "pull_request:" in workflow
    assert "workflow_dispatch:" in workflow
    assert 'branches: ["main"]' in workflow
    assert "samples/host_events/clean_events.json" in workflow
    assert "suppressions/example_suppressions.json" in workflow
    assert "reports/examples/ci_events_report.md" in workflow


def test_codeql_workflow_analyzes_python_with_security_quality_queries() -> None:
    workflow = read(".github/workflows/codeql.yml")

    assert "languages: python" in workflow
    assert "queries: security-and-quality" in workflow
    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "github/codeql-action/analyze@v3" in workflow


def test_dependabot_updates_pip_and_actions_weekly_only() -> None:
    config = read(".github/dependabot.yml")

    assert 'package-ecosystem: "pip"' in config
    assert 'package-ecosystem: "github-actions"' in config
    assert config.count('interval: "weekly"') == 2
    assert "docker" not in config.lower()
    assert "daily" not in config.lower()


def test_docs_check_script_exists_and_is_documented() -> None:
    script = ROOT / "scripts" / "check-docs.py"

    assert script.is_file()
    assert "scripts/check-docs.py" in read(".github/workflows/ci.yml")
