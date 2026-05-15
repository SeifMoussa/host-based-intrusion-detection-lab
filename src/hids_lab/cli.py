"""Command-line interface for the safe HIDS lab."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hids_lab import __version__
from hids_lab.baseline import create_baseline, load_baseline, write_baseline
from hids_lab.detections import detect_events, summarize_alerts
from hids_lab.events import load_events_file, validate_event_input_path
from hids_lab.fim import compare_to_baseline
from hids_lab.reports import build_report_data, write_report
from hids_lab.suppressions import apply_suppressions, count_suppressed, load_suppressions


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="hids-lab",
        description="Safe educational host-based intrusion detection lab.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"hids_lab {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    baseline_parser = subparsers.add_parser("baseline", help="Manage JSON baselines.")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command")
    baseline_create = baseline_subparsers.add_parser(
        "create",
        help="Create a JSON baseline from an explicit safe sample directory.",
    )
    baseline_create.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Sample directory to scan.",
    )
    baseline_create.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Baseline JSON output path.",
    )
    baseline_create.set_defaults(handler=handle_baseline_create)

    fim_parser = subparsers.add_parser("fim", help="Run file integrity monitoring commands.")
    fim_subparsers = fim_parser.add_subparsers(dest="fim_command")
    fim_compare = fim_subparsers.add_parser(
        "compare",
        help="Compare a JSON baseline with an explicit safe sample directory.",
    )
    fim_compare.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="Baseline JSON file.",
    )
    fim_compare.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Sample directory to compare.",
    )
    fim_compare.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format.",
    )
    fim_compare.set_defaults(handler=handle_fim_compare)

    events_parser = subparsers.add_parser("events", help="Validate and detect synthetic events.")
    events_subparsers = events_parser.add_subparsers(dest="events_command")
    events_validate = events_subparsers.add_parser(
        "validate",
        help="Validate an explicit synthetic JSON/CSV event sample.",
    )
    events_validate.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Synthetic event sample under samples/host_events.",
    )
    events_validate.set_defaults(handler=handle_events_validate)

    events_detect = events_subparsers.add_parser(
        "detect",
        help="Run built-in synthetic detection rules against an event sample.",
    )
    events_detect.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Synthetic event sample under samples/host_events.",
    )
    events_detect.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format.",
    )
    add_suppression_args(events_detect)
    events_detect.set_defaults(handler=handle_events_detect)

    report_parser = subparsers.add_parser("report", help="Generate synthetic lab reports.")
    report_subparsers = report_parser.add_subparsers(dest="report_command")
    report_events = report_subparsers.add_parser(
        "events",
        help="Generate a report from synthetic event detections.",
    )
    add_report_output_args(report_events)
    add_suppression_args(report_events)
    report_events.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Synthetic event sample under samples/host_events.",
    )
    report_events.set_defaults(handler=handle_report_events)

    report_fim = report_subparsers.add_parser(
        "fim",
        help="Generate a report from file integrity findings.",
    )
    add_report_output_args(report_fim)
    report_fim.add_argument("--baseline", required=True, type=Path, help="Baseline JSON file.")
    report_fim.add_argument("--root", required=True, type=Path, help="Sample directory to compare.")
    report_fim.set_defaults(handler=handle_report_fim)

    report_combined = report_subparsers.add_parser(
        "combined",
        help="Generate a combined synthetic event and FIM report.",
    )
    add_report_output_args(report_combined)
    add_suppression_args(report_combined)
    report_combined.add_argument(
        "--events",
        required=True,
        type=Path,
        help="Synthetic event sample under samples/host_events.",
    )
    report_combined.add_argument("--baseline", required=True, type=Path, help="Baseline JSON file.")
    report_combined.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Sample directory to compare.",
    )
    report_combined.set_defaults(handler=handle_report_combined)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "handler"):
        parser.print_help()
        return 0

    try:
        return args.handler(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def handle_baseline_create(args: argparse.Namespace) -> int:
    """Handle baseline creation."""
    baseline = create_baseline(args.root)
    write_baseline(baseline, args.output)
    print(json.dumps(baseline, indent=2))
    return 0


def handle_fim_compare(args: argparse.Namespace) -> int:
    """Handle FIM comparison."""
    baseline = load_baseline(args.baseline)
    findings = compare_to_baseline(baseline, args.root)
    if args.format == "text":
        for finding in findings:
            print(f"{finding['status']}: {finding['relative_path']} - {finding['explanation']}")
    else:
        print(json.dumps({"findings": findings}, indent=2))
    return 0


def handle_events_validate(args: argparse.Namespace) -> int:
    """Handle synthetic event validation."""
    event_path = validate_event_input_path(args.input)
    events = load_events_file(event_path)
    print(json.dumps({"status": "valid", "event_count": len(events)}, indent=2))
    return 0


def handle_events_detect(args: argparse.Namespace) -> int:
    """Handle synthetic event detection."""
    event_path = validate_event_input_path(args.input)
    events = load_events_file(event_path)
    alerts = detect_events(events)
    suppressions = load_suppressions(args.suppressions) if args.suppressions else []
    alert_payloads = apply_suppressions(
        alerts,
        suppressions,
        include_suppressed=args.include_suppressed,
    )
    suppression_counts = count_suppressed(
        apply_suppressions(alerts, suppressions, include_suppressed=True)
    )
    payload = {
        "summary": {
            **summarize_alerts(alerts),
            **suppression_counts,
            "visible": len(alert_payloads),
        },
        "alerts": alert_payloads,
    }
    if args.format == "text":
        print(f"alerts: {payload['summary']['visible']}")
        print(f"suppressed: {payload['summary']['suppressed']}")
        for alert in alert_payloads:
            suffix = " suppressed" if alert["suppressed"] else ""
            print(
                f"{alert['severity']}: {alert['rule_id']} - "
                f"{alert['title']} - {alert['evidence']}{suffix}"
            )
    else:
        print(json.dumps(payload, indent=2))
    return 0


def add_report_output_args(parser: argparse.ArgumentParser) -> None:
    """Add common report output arguments."""
    parser.add_argument("--output", required=True, type=Path, help="Report output path.")
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Report output format.",
    )


def add_suppression_args(parser: argparse.ArgumentParser) -> None:
    """Add common suppression arguments."""
    parser.add_argument(
        "--suppressions",
        type=Path,
        help="Optional explicit suppression JSON file.",
    )
    parser.add_argument(
        "--include-suppressed",
        action="store_true",
        help="Include suppressed alerts with suppression metadata.",
    )


def handle_report_events(args: argparse.Namespace) -> int:
    """Generate an event detection report."""
    event_path = validate_event_input_path(args.input)
    events = load_events_file(event_path)
    alerts = detect_events(events)
    suppressions = load_suppressions(args.suppressions) if args.suppressions else []
    report = build_report_data(
        title="Synthetic Host-Event Detection Report",
        inputs={"events": str(args.input)},
        event_alerts=alerts,
        suppressions=suppressions,
        include_suppressed=args.include_suppressed,
    )
    write_report(report, args.output, report_format=args.format)
    print(json.dumps({"status": "written", "output": str(args.output)}, indent=2))
    return 0


def handle_report_fim(args: argparse.Namespace) -> int:
    """Generate a FIM report."""
    baseline = load_baseline(args.baseline)
    findings = compare_to_baseline(baseline, args.root)
    report = build_report_data(
        title="Synthetic File Integrity Report",
        inputs={"baseline": str(args.baseline), "root": str(args.root)},
        fim_findings=findings,
    )
    write_report(report, args.output, report_format=args.format)
    print(json.dumps({"status": "written", "output": str(args.output)}, indent=2))
    return 0


def handle_report_combined(args: argparse.Namespace) -> int:
    """Generate a combined event and FIM report."""
    event_path = validate_event_input_path(args.events)
    events = load_events_file(event_path)
    alerts = detect_events(events)
    baseline = load_baseline(args.baseline)
    findings = compare_to_baseline(baseline, args.root)
    suppressions = load_suppressions(args.suppressions) if args.suppressions else []
    report = build_report_data(
        title="Synthetic Combined HIDS Lab Report",
        inputs={
            "events": str(args.events),
            "baseline": str(args.baseline),
            "root": str(args.root),
        },
        event_alerts=alerts,
        fim_findings=findings,
        suppressions=suppressions,
        include_suppressed=args.include_suppressed,
    )
    write_report(report, args.output, report_format=args.format)
    print(json.dumps({"status": "written", "output": str(args.output)}, indent=2))
    return 0
