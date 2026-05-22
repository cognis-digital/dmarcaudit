"""DMARCAUDIT — Grade SPF/DKIM/DMARC posture & spoofability from DNS records."""
from dmarcaudit.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
