# Host-Based Intrusion Detection Lab

[![CI](https://github.com/SeifMoussa/host-based-intrusion-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SeifMoussa/host-based-intrusion-detection-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SeifMoussa/host-based-intrusion-detection-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/SeifMoussa/host-based-intrusion-detection-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Defensive blue-team / SOC portfolio lab for host-based intrusion detection concepts.

This is a lab-only project built from synthetic local data. It does not monitor real endpoints, collect real OS process lists, scan real system paths, collect credentials, or perform remediation. CI/CodeQL configured but not yet GitHub-verified.

## Project Summary

The lab demonstrates a safe host-based intrusion detection workflow using:

- Synthetic JSON/CSV host-event samples.
- Harmless local sample files.
- JSON file integrity baselines.
- SHA-256 file integrity comparison.
- Transparent synthetic detection rules.
- Explicit suppression handling for expected false positives.
- Markdown and JSON reporting.
- Local tests, coverage, docs checks, and configured GitHub workflows.

The project is intentionally deterministic and public GitHub-friendly.

## Target Job Relevance

This project maps to:

- SOC Analyst
- Blue Team Analyst
- Detection Engineer
- Security Automation Analyst

It demonstrates practical familiarity with alert triage, file integrity monitoring, detection logic, false-positive handling, report writing, test automation, and safe security engineering practices.

## What This Demonstrates

- Building and validating JSON baselines.
- Comparing current sample files to a saved baseline.
- Detecting unchanged, modified, added, and deleted files.
- Parsing static synthetic JSON/CSV host-event records.
- Running transparent rule-based host-event detections.
- Normalizing event detections and FIM findings into alerts.
- Suppressing expected synthetic false positives without deleting evidence.
- Generating Markdown and JSON reports.
- Testing safety boundaries and negative input handling.

## Tech Stack

- Python 3.12
- pytest
- pytest-cov
- ruff
- argparse CLI
- JSON baseline storage
- JSON/CSV synthetic event samples
- Markdown/JSON reports
- GitHub Actions CI configured locally
- CodeQL configured locally
- Dependabot configured locally

## Safety Boundaries

Allowed:

- Synthetic host-event records under `samples/host_events/`.
- Safe text sample files under `samples/files/`.
- Explicit local sample paths inside this repository.
- JSON baselines and generated reports from local lab data.

Not allowed:

- Malware.
- Exploit code.
- Persistence or evasion logic.
- Real credentials, API keys, or tokens.
- Real logs or real indicators.
- Real OS process collection.
- Background agents.
- Real system path monitoring.
- Destructive remediation.
- Third-party scanning.

This is not a production HIDS, EDR, or SIEM.

## File Integrity Monitoring

The FIM workflow is:

1. Create a JSON baseline from an explicit sample directory.
2. Store repo-relative file path, SHA-256, size, modified time, and baseline status.
3. Compare a current explicit sample directory to the saved baseline.
4. Classify files as `unchanged`, `modified`, `added`, or `deleted`.

Example:

```powershell
python -m hids_lab baseline create --root samples/files/clean --output baselines/generated_baseline.json
python -m hids_lab fim compare --baseline baselines/generated_baseline.json --root samples/files/clean
```

## Host-Event Detection

Host-event detection operates only on static synthetic JSON/CSV records.

Built-in rules include:

- `HIDS-PROC-001`: synthetic suspicious command marker.
- `HIDS-PROC-002`: fake lab scheduler parent marker.
- `HIDS-FILE-001`: synthetic config modification event.
- `HIDS-AUTH-001`: repeated fake auth failure records.
- `HIDS-LAB-001`: known lab suspicious marker.

Example:

```powershell
python -m hids_lab events validate --input samples/host_events/clean_events.json
python -m hids_lab events detect --input samples/host_events/suspicious_events.json --format json
python -m hids_lab events detect --input samples/host_events/mixed_events.csv --format text
```

## Suppression Workflow

Suppressions are explicit JSON entries under `suppressions/`. They can hide expected synthetic false positives from normal output while preserving evidence and reason metadata.

Example:

```powershell
python -m hids_lab events detect --input samples/host_events/false_positive_events.json --suppressions suppressions/example_suppressions.json --format json --include-suppressed
```

Suppressed alerts include:

- `suppressed`
- `suppression_id`
- `suppression_reason`

## Reports

Reports support Markdown and JSON output.

Examples:

```powershell
python -m hids_lab report events --input samples/host_events/suspicious_events.json --output reports/events_report.md --format markdown
python -m hids_lab report fim --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/fim_report.md --format markdown
python -m hids_lab report combined --events samples/host_events/suspicious_events.json --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/combined_report.md --format markdown
```

Stable example reports:

- [events_suspicious_report.md](reports/examples/events_suspicious_report.md)
- [fim_clean_report.md](reports/examples/fim_clean_report.md)
- [combined_lab_report.md](reports/examples/combined_lab_report.md)
- [combined_lab_report.json](reports/examples/combined_lab_report.json)

All report examples are generated from synthetic local lab data.

## CLI Quick Reference

```powershell
python -m hids_lab --help
python -m hids_lab baseline create --root samples/files/clean --output baselines/generated_baseline.json
python -m hids_lab fim compare --baseline baselines/generated_baseline.json --root samples/files/clean
python -m hids_lab events validate --input samples/host_events/clean_events.json
python -m hids_lab events detect --input samples/host_events/suspicious_events.json --format json
python -m hids_lab events detect --input samples/host_events/false_positive_events.json --suppressions suppressions/example_suppressions.json --format json --include-suppressed
python -m hids_lab report events --input samples/host_events/suspicious_events.json --output reports/events_report.md --format markdown
python -m hids_lab report fim --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/fim_report.md --format markdown
python -m hids_lab report combined --events samples/host_events/suspicious_events.json --baseline baselines/generated_baseline.json --root samples/files/clean --output reports/combined_report.md --format markdown
```

## Testing

Local verification status:

- `pytest`: 97 passed.
- Coverage: 95.59%.
- Coverage gate: 90%.
- `ruff check`: passed.
- `ruff format --check`: passed.
- `python scripts/check-docs.py`: passed.
- CLI smoke commands: passed locally.

Run:

```powershell
python -m pytest
python -m pytest --cov=hids_lab --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
```

CI/CodeQL configured but not yet GitHub-verified.

## Project Structure

```text
src/hids_lab/          Python package
samples/              Synthetic host-event records and safe sample files
baselines/            Example JSON baseline
reports/examples/     Stable synthetic report examples
suppressions/         Explicit suppression examples
docs/                 Project documentation
tests/                Unit, integration, safety, docs, and workflow tests
scripts/              Documentation safety checker
.github/workflows/    CI and CodeQL workflow configuration
```

## Known Limitations

- CI and CodeQL have not yet run on GitHub.
- No release or tag has been created.
- No live endpoint telemetry is collected by design.
- No background monitoring is implemented by design.
- No real system paths are scanned by design.
- No destructive remediation is performed by design.
- SQLite baseline storage is optional future work; JSON is the primary format.

## License

MIT. See [LICENSE](LICENSE).
