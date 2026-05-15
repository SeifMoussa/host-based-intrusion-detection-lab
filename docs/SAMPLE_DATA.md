# Sample Data

All sample data is synthetic, local, and safe for public review.

## Host-Event Samples

Host-event samples live in `samples/host_events/`.

Current files:

- `clean_events.json`: harmless clean process/file-read records.
- `suspicious_events.json`: synthetic records designed to trigger lab rules.
- `mixed_events.csv`: CSV sample with clean, suspicious, and fake auth records.
- `false_positive_events.json`: synthetic false-positive scenario for suppression testing.
- `malformed_events.json`: intentionally incomplete data for validation tests.

Required event fields:

- `timestamp`
- `host`
- `event_type`
- `process_name`
- `command_line`
- `user`
- `parent_process`
- `file_path`
- `action`
- `synthetic_label`
- `lab_marker`

All records use fake values such as `lab-host-01`, `lab_user`, and paths under `samples/files/`.

## Safe Sample Files

Sample files live in:

- `samples/files/clean/`
- `samples/files/modified/`
- `samples/files/new/`

They are harmless UTF-8 text files. Binary samples are not used.

## Baseline Samples

`baselines/example_baseline.json` is a stable example baseline for `samples/files/clean/`.

Generated baselines include:

- `baseline_version`
- `generated_at`
- `root_path`
- `files`

Each file entry includes:

- `relative_path`
- `sha256`
- `size_bytes`
- `modified_time_utc`
- `status`

Generated temporary baselines such as `baselines/generated_baseline.json` and `baselines/ci_generated_baseline.json` are ignored.

## Suppression Samples

`suppressions/example_suppressions.json` demonstrates explicit false-positive suppression for synthetic alerts.

Suppressions preserve alert evidence and reason metadata.

## Safety Rules

Sample data must not include real credentials, API keys, tokens, real logs, real indicators, public IP addresses, real domains, malware, exploit content, persistence content, evasion content, or third-party scanning targets.
