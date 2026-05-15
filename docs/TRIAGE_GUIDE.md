# Triage Guide

Phase 4 adds normalized alerts from synthetic host-event detections.

## Severity

- `low`: useful lab context or intentionally suspicious label.
- `medium`: synthetic activity worth analyst review in the exercise.
- `high`: synthetic file activity that should be compared with the lab baseline.
- `critical`: reserved for future safe lab scenarios.

## Alert Fields

Each alert includes:

- `alert_id`
- `timestamp`
- `severity`
- `category`
- `rule_id`
- `title`
- `description`
- `evidence`
- `recommended_action`
- `source`
- `status`
- `tags`
- `synthetic`

Recommended actions are triage guidance only. The project does not perform live response, destructive changes, or system remediation.

## Report Interpretation

Phase 5 reports combine host-event detection alerts and file integrity findings into one analyst-friendly view.

Report sections:

- Executive summary: total alerts and source-specific counts.
- Alert count by severity: quick prioritization view.
- File integrity findings summary: counts for modified, added, deleted, and unchanged files.
- Host-event detections summary: count of synthetic event alerts.
- Detailed alert table: evidence and recommended analyst action for each alert.
- Limitations: reminder that reports are synthetic lab artifacts only.

Use high-severity findings first during triage practice, then review medium and low findings for context.

## False-Positive And Suppression Workflow

Phase 6 adds explicit suppressions for expected synthetic false positives.

Workflow:

1. Review the alert evidence.
2. Confirm the alert is expected lab behavior.
3. Add or reference an explicit suppression entry.
4. Preserve the suppression reason.
5. Use `--include-suppressed` when a review needs to show hidden alerts.

Suppression does not delete evidence. It adds metadata such as `suppressed`, `suppression_id`, and `suppression_reason`.
