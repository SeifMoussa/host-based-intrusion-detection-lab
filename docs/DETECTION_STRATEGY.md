# Detection Strategy

Detection is intentionally transparent, deterministic, and limited to synthetic local lab data.

This project does not collect live endpoint telemetry, inspect real OS process lists, monitor real system paths, perform remediation, or claim production HIDS/EDR/SIEM capability.

## File Integrity Monitoring

FIM operates on explicit sample directories only.

Workflow:

1. Create a JSON baseline from a user-provided root under `samples/`.
2. Store SHA-256, size, modified time, status, and repo-relative file path.
3. Compare a saved baseline to the current state of an explicit root.
4. Classify files as `unchanged`, `modified`, `added`, or `deleted`.
5. Convert FIM findings into normalized alerts for reporting.

## Host-Event Detection

Host-event rules operate only on static synthetic JSON/CSV records under `samples/host_events/`.

Rule fields:

- `rule_id`
- `name`
- `description`
- `severity`
- `category`
- `event_type`
- `field`
- `match_type`
- `pattern`
- `explanation`
- `recommended_action`
- `tags`
- `enabled`

Supported match types:

- `contains`
- `equals`
- `regex`
- `count_gte`

Built-in rules:

- `HIDS-PROC-001`: synthetic command-line marker.
- `HIDS-PROC-002`: fake lab scheduler parent marker.
- `HIDS-FILE-001`: synthetic modified config write event.
- `HIDS-AUTH-001`: repeated fake auth failure records.
- `HIDS-LAB-001`: known lab suspicious marker.

Rules are based on lab-only fields and markers. They do not use real indicators, real malware names, real domains, or live telemetry.

## Alert And Report Flow

Flow:

1. Load explicit synthetic inputs.
2. Run FIM comparison or host-event rules.
3. Normalize findings into alerts.
4. Apply explicit suppressions if provided.
5. Build severity counts and summaries.
6. Render Markdown or JSON reports.

Reports include a defensive lab-only disclaimer.

## Suppression Strategy

Suppressions are explicit JSON entries that can match:

- `rule_id`
- source text
- evidence text

Suppressed alerts preserve evidence and add:

- `suppressed`
- `suppression_id`
- `suppression_reason`

Normal output can hide suppressed alerts. `--include-suppressed` includes them for review.

## Quality Validation

Validation covers malformed events, malformed baselines, malformed suppression files, unsupported formats, empty event samples, clean-data expectations, report safety, workflow configuration, docs consistency, and FIM regression behavior.

CI/CodeQL configured but not yet GitHub-verified.
