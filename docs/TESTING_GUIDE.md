# Testing Guide

Run project checks with:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## CI Expectations

CI/CodeQL configured but not yet GitHub-verified.

The local CI-equivalent checks are:

```powershell
python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
```

The configured GitHub Actions CI has `tests`, `docs`, and `cli-smoke` jobs. It uses Python 3.12 and enforces the 90% coverage gate.

## FIM Checks

FIM tests cover:

- SHA-256 calculation.
- Baseline generation from `samples/files/clean`.
- Baseline JSON shape.
- Relative baseline file paths.
- Unchanged, modified, added, and deleted file findings.
- Non-mutating comparison behavior.
- Unsafe path traversal rejection.
- Nonexistent and out-of-scope root rejection.
- CLI baseline creation.
- CLI FIM comparison.
- CLI invalid path handling.

## Detection Checks

Detection tests cover:

- Default rule loading.
- Unique rule IDs.
- Valid severity values.
- `contains`, `equals`, `regex`, and `count_gte` matches.
- Disabled rule skipping.
- Clean samples avoiding high and critical alerts.
- Suspicious JSON samples producing expected alerts.
- Mixed CSV samples producing expected alerts.
- Malformed event input failure.
- Normalized alert fields.
- `events validate` CLI behavior.
- `events detect` JSON and text output.
- Rule safety boundaries.

Manual CLI examples:

```powershell
$env:PYTHONPATH='src'; python -m hids_lab events validate --input samples/host_events/clean_events.json
$env:PYTHONPATH='src'; python -m hids_lab events detect --input samples/host_events/suspicious_events.json --format json
$env:PYTHONPATH='src'; python -m hids_lab events detect --input samples/host_events/mixed_events.csv --format text
```

## Report Checks

Report tests cover:

- Markdown event report generation.
- JSON event report generation.
- FIM report generation.
- Combined report generation.
- Severity counts.
- Safety disclaimer presence.
- Triage recommendation presence.
- Host-event and FIM content in reports.
- Report content avoiding real-world indicators.
- CLI report generation for events, FIM, and combined workflows.

Manual CLI examples:

```powershell
$env:PYTHONPATH='src'; python -m hids_lab report events --input samples/host_events/suspicious_events.json --output reports/events_report.md --format markdown
$env:PYTHONPATH='src'; python -m hids_lab report fim --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/fim_report.md --format markdown
$env:PYTHONPATH='src'; python -m hids_lab report combined --events samples/host_events/suspicious_events.json --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/combined_report.md --format markdown
```

## Quality And Suppression Checks

Quality and suppression tests cover:

- Explicit suppression loading.
- Suppressed alert hiding by default.
- Suppressed alert metadata with `--include-suppressed`.
- Invalid suppression JSON and schema failures.
- Malformed JSON/CSV event failures.
- Malformed baseline failures.
- Unsupported event and report formats.
- Empty event samples.
- No-alert report behavior.
- Expanded synthetic-data safety validation.
- Report example safety disclaimers.
- Coverage gate of 90%.

Coverage command:

```powershell
python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90
```

Manual CLI examples:

```powershell
$env:PYTHONPATH='src'; python -m hids_lab baseline create --root samples/files/clean --output baselines/generated_baseline.json
$env:PYTHONPATH='src'; python -m hids_lab fim compare --baseline baselines/generated_baseline.json --root samples/files/clean
```
