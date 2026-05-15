"""Tests for the Phase 1 CLI placeholder."""

from hids_lab.cli import main


def test_cli_help(capsys) -> None:
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    captured = capsys.readouterr()
    assert "Safe educational host-based intrusion detection lab" in captured.out
