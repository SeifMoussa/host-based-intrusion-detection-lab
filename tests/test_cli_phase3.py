"""CLI tests for Phase 3 baseline and FIM commands."""

from __future__ import annotations

import json
from pathlib import Path

from hids_lab.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CLEAN = ROOT / "samples" / "files" / "clean"


def test_cli_baseline_create_works(tmp_path: Path, capsys) -> None:
    output = tmp_path / "generated_baseline.json"

    exit_code = main(
        [
            "baseline",
            "create",
            "--root",
            str(SAMPLE_CLEAN),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert output.exists()
    assert payload["root_path"] == "samples/files/clean"


def test_cli_fim_compare_works(tmp_path: Path, capsys) -> None:
    output = tmp_path / "generated_baseline.json"
    assert (
        main(
            [
                "baseline",
                "create",
                "--root",
                str(SAMPLE_CLEAN),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    capsys.readouterr()

    exit_code = main(["fim", "compare", "--baseline", str(output), "--root", str(SAMPLE_CLEAN)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert {finding["status"] for finding in payload["findings"]} == {"unchanged"}


def test_cli_invalid_paths_fail_safely(capsys) -> None:
    exit_code = main(
        [
            "baseline",
            "create",
            "--root",
            str(ROOT),
            "--output",
            "baselines/should_not_write.json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "allowed sample area" in captured.err
