# Synthetic Host-Event Detection Report

Generated: 2026-01-15T12:30:00Z

## Safety Disclaimer

Defensive lab-only report generated from synthetic local sample data. This project does not collect live endpoint telemetry, monitor real system paths, perform response actions, or claim production EDR/SIEM capability.

## Input Sources

- events: `samples/host_events/suspicious_events.json`

## Executive Summary

- Total alerts: 8
- Host-event detections: 8
- File integrity findings: 0

## Alert Count By Severity

- critical: 0
- high: 1
- medium: 2
- low: 5

## File Integrity Findings Summary

- No file integrity findings included.

## Host-Event Detections Summary

- Host-event alerts: 8

## Detailed Alert Table

| Severity | Rule | Title | Evidence | Recommended Action |
| --- | --- | --- | --- | --- |
| high | HIDS-FILE-001 | Synthetic config modification event | file_path=samples/files/modified/app_settings.json | Compare the file with the approved lab baseline and document the change. |
| medium | HIDS-PROC-001 | Synthetic suspicious command marker | command_line=lab-script-runner --simulate-unusual-file-review | Review the synthetic event context and confirm it is expected lab data. |
| medium | HIDS-AUTH-001 | Repeated synthetic login failures | user=lab_user; count=2 | Review the fake auth events and record the training scenario outcome. |

## Triage Recommendations

- Review high-severity synthetic findings first.
- Confirm all paths reference local lab sample files.
- Use the evidence field to explain why each rule matched.
- Document analyst notes separately from generated output.

## Limitations

- Synthetic-only lab report.
- No live endpoint telemetry collection.
- No production EDR/SIEM capability is claimed.
- No response or file changes are performed.

