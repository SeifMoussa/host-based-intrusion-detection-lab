# Requirements

This project is a defensive, synthetic-data host-based intrusion detection lab.

## Completed Capabilities

- Repository scaffold and Python package layout.
- Synthetic JSON/CSV host-event samples.
- Safe local text sample files.
- JSON baseline format and generation.
- File integrity monitoring comparison.
- Host-event detection rules.
- Normalized alert model.
- Explicit suppression handling for synthetic false positives.
- Markdown and JSON report generation.
- Safety validation and negative tests.
- Documentation safety checker.
- GitHub Actions CI configured locally.
- CodeQL configured locally.
- Dependabot configured for weekly pip and GitHub Actions updates.

CI/CodeQL configured but not yet GitHub-verified.

## Primary Storage

JSON is the primary baseline storage format.

SQLite may be considered later as an optional enhancement, but it is not required for the current lab.

## Required Safety Scope

The lab uses only:

- Synthetic host-event records.
- Safe local sample files.
- Explicit repo-controlled paths.
- Local JSON baselines.
- Locally generated reports.

The lab excludes:

- Malware.
- Exploit code.
- Persistence or evasion logic.
- Real credentials.
- Real logs.
- Real indicators.
- Real OS process collection.
- Background agents.
- Real system path monitoring.
- Destructive remediation.
- Third-party scanning.

## Verification Requirements

Current local verification:

- 97 tests pass.
- Coverage is 95.59%.
- Coverage gate is 90%.
- Ruff check passes.
- Ruff format check passes.
- Documentation safety check passes.
- CLI smoke commands pass locally.

GitHub Actions and CodeQL must be verified on GitHub only after publishing.
