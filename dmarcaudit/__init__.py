"""DMARCAUDIT — grade SPF/DKIM/DMARC posture & spoofability from DNS records.

Defensive email-authentication forensics. Parses the email-auth DNS records you
own (SPF/DKIM/DMARC) and grades how easily an attacker could spoof your domain.
Standard library only, zero install, offline.
"""
from .core import (
    audit_domain,
    parse_spf,
    parse_dmarc,
    parse_dkim,
    grade,
    Finding,
    AuditResult,
    SEVERITY_ORDER,
)

TOOL_NAME = "dmarcaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "audit_domain",
    "parse_spf",
    "parse_dmarc",
    "parse_dkim",
    "grade",
    "Finding",
    "AuditResult",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
