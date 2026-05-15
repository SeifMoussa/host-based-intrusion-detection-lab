# Testing Report

Phase 9 release-preparation testing report.

## Commands

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
$env:PYTHONPATH='src'; python -m hids_lab --help
$env:PYTHONPATH='src'; python -m hids_lab baseline create --root samples/files/clean --output baselines/generated_baseline.json
$env:PYTHONPATH='src'; python -m hids_lab fim compare --baseline baselines/generated_baseline.json --root samples/files/clean
$env:PYTHONPATH='src'; python -m hids_lab events validate --input samples/host_events/clean_events.json
$env:PYTHONPATH='src'; python -m hids_lab events detect --input samples/host_events/suspicious_events.json --format json
$env:PYTHONPATH='src'; python -m hids_lab events detect --input samples/host_events/mixed_events.csv --format text
$env:PYTHONPATH='src'; python -m hids_lab report events --input samples/host_events/suspicious_events.json --output reports/events_report.md --format markdown
$env:PYTHONPATH='src'; python -m hids_lab report fim --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/fim_report.md --format markdown
$env:PYTHONPATH='src'; python -m hids_lab report combined --events samples/host_events/suspicious_events.json --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/combined_report.md --format markdown
python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90
$env:PYTHONPATH='src'; python -m hids_lab events detect --input samples/host_events/false_positive_events.json --suppressions suppressions/example_suppressions.json --format json --include-suppressed
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
```

## Latest Results

- `python -m pytest`: 97 passed.
- `python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90`: 97 passed, total coverage 95.59%.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 28 files already formatted.
- `python scripts/check-docs.py`: passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- Representative CLI smoke commands passed locally.
- Release preparation materials completed in `RELEASE.md`.
- Transient `baselines/ci_generated_baseline.json` and `reports/examples/ci_events_report.md` were removed after validation.
- CI/CodeQL configured but not yet GitHub-verified.

## Previous Phase 8 Results

- `python -m pytest`: 97 passed.
- `python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90`: 97 passed, total coverage 95.59%.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 28 files already formatted.
- `python scripts/check-docs.py`: passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- Required repository paths are present.
- Safety/hygiene audit found no committed `.env`, virtual environment, cache, coverage, or generated baseline/report artifacts intended for commit.
- CLI QA commands passed locally.
- Workflow QA tests passed locally.
- CI/CodeQL configured but not yet GitHub-verified.

## Previous Phase 7 Results

- `python -m pytest`: 97 passed.
- `python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90`: 97 passed, total coverage 95.59%.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 28 files already formatted.
- `python scripts/check-docs.py`: passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- Representative CLI smoke commands passed locally.
- CI/CodeQL configured but not yet GitHub-verified.

## Previous Phase 6 Results

- `python -m pytest`: 90 passed.
- `python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90`: 90 passed, total coverage 95.59%.
- Coverage gate is 90%.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 25 files already formatted.

## Previous Phase 5 Results

- `python -m pytest`: 59 passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 21 files already formatted.
- Existing CLI and report examples passed.

## Previous Phase 4 Results

- `python -m pytest`: 48 passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 20 files already formatted.
- Event CLI examples passed.
- Phase 3 baseline create and FIM compare commands passed.

## Previous Phase 3 Results

- `python -m pytest`: 28 passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 18 files already formatted.
- FIM CLI examples passed.

## Previous Phase 2 Results

- `python -m pytest`: 15 passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 16 files already formatted.
- `$env:PYTHONPATH='src'; python -m hids_lab --help`: help output displayed successfully.

## Coverage Added

- Valid JSON host-event loading.
- Valid CSV host-event loading.
- Malformed JSON event data rejection.
- Required event field validation.
- Baseline shape validation.
- Baseline file entry validation.
- Synthetic sample safety checks.
- Safe text sample file checks.
- SHA-256 calculation.
- Baseline generation.
- File integrity comparison.
- CLI baseline creation.
- CLI FIM comparison.
- Safe path rejection.
- Detection rule validation.
- Event detection matching.
- Normalized alert fields.
- Event CLI validation and detection.
- Detection rule safety checks.
- Markdown and JSON report rendering.
- Event, FIM, and combined report generation.
- Report CLI commands.
- Explicit suppression handling.
- False-positive sample validation.
- Negative parser and format tests.
- Expanded safety validation.
- Coverage reporting.
- Coverage hardening to a 90% gate after reaching 95.59% actual coverage.
- GitHub Actions CI configured locally.
- CodeQL workflow configured locally.
- Dependabot configured for weekly pip and GitHub Actions updates.
- Documentation safety checker added.
- Workflow and documentation consistency tests added.
- Phase 8 README and documentation completion.
- Phase 8 repository structure, safety, CLI, workflow, and docs QA.
- Phase 9 release preparation materials.
- Manual GitHub publishing command plan.
- v0.1.0 release notes draft.
- Portfolio output drafts.

CI/CodeQL configured but not yet GitHub-verified. Background monitoring and real OS collection are intentionally excluded to keep the lab safe, deterministic, and public GitHub-friendly.
