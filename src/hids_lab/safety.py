"""Safety validation helpers for synthetic lab samples."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

FORBIDDEN_SAMPLE_TERMS = frozenset(
    {
        "api_key",
        "apikey",
        "bearer",
        "credential",
        "destructive",
        "evasion",
        "exploit",
        "malware",
        "password",
        "persistence",
        "privilege escalation",
        "remediation",
        "real log",
        "secret",
        "token",
    }
)

DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RESERVED_DOMAIN_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
LOCAL_FILE_SUFFIXES = (".csv", ".json", ".md", ".txt")


def path_is_inside(child: Path, parent: Path) -> bool:
    """Return whether child resolves inside parent."""
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def find_forbidden_terms(text: str) -> set[str]:
    """Find prohibited terms in synthetic sample content."""
    lowered = text.lower()
    return {term for term in FORBIDDEN_SAMPLE_TERMS if term in lowered}


def find_public_ipv4_addresses(text: str) -> set[str]:
    """Find public IPv4 addresses in text."""
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
    """Find domains that are not reserved for documentation or local testing."""
    domains = set()
    for candidate in DOMAIN_PATTERN.findall(text):
        normalized = candidate.lower()
        if not normalized.endswith(RESERVED_DOMAIN_SUFFIXES + LOCAL_FILE_SUFFIXES):
            domains.add(candidate)
    return domains
