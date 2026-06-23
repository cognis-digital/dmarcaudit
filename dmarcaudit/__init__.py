"""dmarcaudit — part of the Cognis Neural Suite.

Grade SPF/DKIM/DMARC posture & spoofability from DNS records, fully offline.
"""
from dmarcaudit.core import (  # noqa: F401
    TOOL_NAME, TOOL_VERSION,
    Finding, AuditResult, SEVERITY_ORDER,
    parse_spf, parse_dmarc, parse_dkim, grade, audit_domain,
    spf_hosts, enrich_with_feeds, scan, to_json,
)

__version__ = TOOL_VERSION
__all__ = [
    "TOOL_NAME", "TOOL_VERSION", "Finding", "AuditResult", "SEVERITY_ORDER",
    "parse_spf", "parse_dmarc", "parse_dkim", "grade", "audit_domain",
    "spf_hosts", "enrich_with_feeds", "scan", "to_json",
]
