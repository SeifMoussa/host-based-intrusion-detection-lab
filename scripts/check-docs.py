"""Repository documentation and safety consistency checks."""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCS = [
    "README.md",
    "TESTING_REPORT.md",
    "PROJECT_COMPLETION_CHECKLIST.md",
    "CHANGELOG.md",
    "docs/SAFETY.md",
    "docs/TESTING_GUIDE.md",
    "docs/DETECTION_STRATEGY.md",
    "docs/TRIAGE_GUIDE.md",
    "docs/SAMPLE_DATA.md",
    "docs/RELEASE_CHECKLIST.md",
]

REQUIRED_EXAMPLES = [
    "reports/examples/events_suspicious_report.md",
    "reports/examples/fim_clean_report.md",
    "reports/examples/combined_lab_report.md",
    "reports/examples/combined_lab_report.json",
]

REQUIRED_COMMANDS = [
    "python -m hids_lab --help",
    "events validate",
    "events detect",
    "baseline create",
    "fim compare",
    "report events",
    "report fim",
    "report combined",
]

FORBIDDEN_CLAIMS = [
    "codeql scan passed",
]

FORBIDDEN_SAFETY_TERMS = [
    "real token",
    "real api key",
    "real incident data",
    "malware sample",
    "exploit instructions",
    "offensive guidance",
]

RESERVED_DOMAIN_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
LOCAL_FILE_SUFFIXES = (".csv", ".json", ".md", ".svg", ".txt", ".yml", ".yaml", ".py")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def main() -> int:
    failures: list[str] = []
    failures.extend(check_required_files())
    failures.extend(check_links())
    failures.extend(check_claims_and_safety_text())
    failures.extend(check_samples_and_docs_for_indicators())
    failures.extend(check_report_examples())
    failures.extend(check_documented_commands())

    if failures:
        for failure in failures:
            print(f"docs-check: {failure}", file=sys.stderr)
        return 1
    print("docs-check: passed")
    return 0


def check_required_files() -> list[str]:
    failures = []
    for relative_path in [*REQUIRED_DOCS, *REQUIRED_EXAMPLES]:
        if not (ROOT / relative_path).is_file():
            failures.append(f"missing required file: {relative_path}")
    return failures


def check_links() -> list[str]:
    failures = []
    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK_PATTERN.findall(text):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            clean_target = target.split("#", maxsplit=1)[0]
            if not clean_target:
                continue
            candidate = (path.parent / clean_target).resolve()
            if not is_inside_repo(candidate) or not candidate.exists():
                failures.append(f"broken local link in {relative(path)}: {target}")
    return failures


def check_claims_and_safety_text() -> list[str]:
    failures = []
    doc_text = all_doc_text().lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim in doc_text:
            failures.append(f"forbidden or premature claim found: {claim}")
    premature_claim_patterns = [
        "ci passed on github",
        "github actions passed",
        "codeql passed",
    ]
    for claim in premature_claim_patterns:
        if claim in doc_text and "after publishing" not in doc_text:
            failures.append(f"forbidden or premature claim found: {claim}")

    required_phrases = [
        "ci/codeql configured but not yet github-verified",
        "background monitoring",
        "intentionally excluded",
        "real os",
        "synthetic",
    ]
    for phrase in required_phrases:
        if phrase not in doc_text:
            failures.append(f"missing required documentation phrase: {phrase}")
    return failures


def check_samples_and_docs_for_indicators() -> list[str]:
    failures = []
    checked_roots = ["README.md", "docs", "samples", "suppressions", "reports/examples"]
    for path in files_under(checked_roots):
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for term in FORBIDDEN_SAFETY_TERMS:
            if term in lowered:
                failures.append(f"unsafe term in {relative(path)}: {term}")
        public_ips = find_public_ipv4_addresses(text)
        if public_ips:
            failures.append(f"public IPv4 address in {relative(path)}: {sorted(public_ips)}")
        domains = find_unreserved_domains(text)
        if domains:
            failures.append(f"unreserved domain in {relative(path)}: {sorted(domains)}")
    return failures


def check_report_examples() -> list[str]:
    failures = []
    for relative_path in REQUIRED_EXAMPLES:
        text = (ROOT / relative_path).read_text(encoding="utf-8").lower()
        if "synthetic" not in text or "local" not in text:
            failures.append(
                f"report example must mention synthetic/local lab data: {relative_path}"
            )
    return failures


def check_documented_commands() -> list[str]:
    failures = []
    text = all_doc_text().lower()
    for command in REQUIRED_COMMANDS:
        if command not in text:
            failures.append(f"missing documented CLI command: {command}")
    return failures


def markdown_files() -> list[Path]:
    return [path for path in ROOT.rglob("*.md") if ".pytest_tmp" not in path.parts]


def files_under(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        path = ROOT / item
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(child for child in path.rglob("*") if child.is_file())
    return files


def all_doc_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in markdown_files())


def find_public_ipv4_addresses(text: str) -> set[str]:
    public_addresses: set[str] = set()
    for candidate in IPV4_PATTERN.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and address.is_global:
            public_addresses.add(candidate)
    return public_addresses


def find_unreserved_domains(text: str) -> set[str]:
    domains = set()
    for candidate in DOMAIN_PATTERN.findall(text):
        normalized = candidate.lower()
        if normalized.startswith(("github.com", "img.shields.io")):
            continue
        if not normalized.endswith(RESERVED_DOMAIN_SUFFIXES + LOCAL_FILE_SUFFIXES):
            domains.add(candidate)
    return domains


def is_inside_repo(path: Path) -> bool:
    try:
        path.relative_to(ROOT)
    except ValueError:
        return False
    return True


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
