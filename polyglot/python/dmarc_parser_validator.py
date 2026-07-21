"""
dmarcaudit: DMARC/SPF/DKIM Parser Validator

A production-grade parser and validator for email authentication records.
Analyzes domain posture and generates prioritized fix recommendations.

Usage:
    python -m polyglot.python.dmarc_parser_validator <domain> [--verbose]
"""

import argparse
import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class PolicyState(Enum):
    """DMARC policy states."""
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    SUBMIT = "submit"  # Legacy, rarely used


class AlignmentMode(Enum):
    """DKIM/SPF alignment modes."""
    RELAXED = "relaxed"
    STRICT = "strict"


@dataclass
class DMARCRecord:
    """Parsed and validated DMARC record data."""
    domain: str
    flags: list[str]
    policy: PolicyState = PolicyState.NONE
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    adkim: AlignmentMode = AlignmentMode.RELAXED
    aspf: AlignmentMode = AlignmentMode.RELAXED
    sp: int = 0
    pct: int = 100
    text: str = ""
    raw: dict[str, str] = field(default_factory=dict)
    
    @classmethod
    def from_text(cls, domain: str, text: str) -> "DMARCRecord":
        """Parse a DMARC TXT record."""
        flags = []
        policy = PolicyState.NONE
        rua = []
        ruf = []
        adkim = AlignmentMode.RELAXED
        aspf = AlignmentMode.RELAXED
        sp = 0
        pct = 100
        
        # Normalize and split
        text = text.strip()
        if not text:
            return cls(domain, flags, policy, rua, ruf, adkim, aspf, sp, pct, text)
        
        parts = text.split()
        
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.lower().strip("-")
                value = value.strip('"')
                
                # Policy
                if key == "p":
                    policy = PolicyState(value.lower())
                    
                # Reporting addresses
                elif key in ("rua", "ruf"):
                    addr_list = [addr.strip() for addr in value.split(",")]
                    rua if key == "rua" else ruf  # type: ignore
                    
                # Alignment modes
                elif key == "adkim":
                    adkim = AlignmentMode(value.lower())
                    
                elif key == "aspf":
                    aspf = AlignmentMode(value.lower())
                    
                # Subdomain policy
                elif key == "sp":
                    try:
                        sp = int(value)
                    except ValueError:
                        pass
                        
                # Percentage (legacy)
                elif key == "pct":
                    try:
                        pct = int(value)
                    except ValueError:
                        pass
        
        return cls(domain, flags, policy, rua, ruf, adkim, aspf, sp, pct, text)


@dataclass
class SPFRecord:
    """Parsed and validated SPF record data."""
    domain: str
    parts: list[str] = field(default_factory=list)
    auth_rate: float = 100.0
    includes: int = 0
    redirects: int = 0
    has_all: bool = False
    all_type: str = ""  # "-all", "+all", "~all"
    raw: dict[str, str] = field(default_factory=dict)
    
    @classmethod
    def from_text(cls, domain: str, text: str) -> "SPFRecord":
        """Parse an SPF TXT record."""
        parts = []
        includes = 0
        redirects = 0
        has_all = False
        all_type = ""
        
        text = text.strip()
        if not text:
            return cls(domain, parts, 100.0, includes, redirects, has_all, all_type)
        
        # Split by whitespace (SPF uses space as delimiter)
        for token in text.split():
            part = token.strip('"')
            
            # Check for include/redirect
            if part.startswith("include:"):
                parts.append(part)
                includes += 1
                
            elif part.startswith("redirect="):
                parts.append(part)
                redirects += 1
                
            # Check for -all, +all, ~all
            elif part in ("-all", "+all", "~all"):
                has_all = True
                all_type = part
        
        return cls(domain, parts, 100.0, includes, redirects, has_all, all_type)


@dataclass
class DKIMRecord:
    """Parsed and validated DKIM public key record."""
    domain: str
    selector: str
    key: str
    algorithm: str = "rsa-sha256"  # Default assumption
    key_length: int = 0
    is_valid: bool = True
    issues: list[str] = field(default_factory=list)
    
    @classmethod
    def from_text(cls, domain: str, selector: str, text: str) -> "DKIMRecord":
        """Parse a DKIM public key record."""
        key = text.strip()
        
        if not key:
            return cls(domain, selector, "", 0, False, ["Empty key"])
        
        # Extract algorithm and base64 key
        parts = key.split(" ", 2)
        algorithm = "rsa-sha256"
        b64_key = ""
        
        if len(parts) >= 3:
            algorithm = parts[1]
            try:
                b64_key = parts[2].strip()
            except IndexError:
                pass
        
        # Decode and validate base64
        issues = []
        key_length = 0
        is_valid = True
        
        if b64_key:
            try:
                decoded = base64.b64decode(b64_key)
                key_length = len(decoded)
                
                # Check for common issues
                if key_length < 128:
                    issues.append(f"Key too short ({key_length} bytes)")
                    
                elif key_length > 4096:
                    issues.append("Key unusually long")
                    
                # Check algorithm consistency
                expected_len = {
                    "rsa-sha256": 128,
                    "rsa-sha384": 192,
                    "rsa-sha512": 256,
                    "ed25519": 32,
                }.get(algorithm)
                
                if expected_len and key_length != expected_len:
                    issues.append(f"Key length mismatch for {algorithm}")
                    
            except binascii.Error as e:
                is_valid = False
                issues.append(f"Invalid base64 encoding: {e}")
        
        return cls(domain, selector, b64_key, algorithm, key_length, is_valid, issues)


class DMARCAuditResult:
    """Aggregated audit results with spoofability score."""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.dmarc: Optional[DMARCRecord] = None
        self.spf: Optional[SPFRecord] = None
        self.dkims: list[DKIMRecord] = []
        self.timestamp = datetime.utcnow()
        
    def add_dmarc(self, record: DMARCRecord) -> None:
        """Add a DMARC record."""
        if not self.dmarc or (self.dmarc.domain != domain):
            self.dmarc = record
            
    def add_spf(self, record: SPFRecord) -> None:
        """Add an SPF record."""
        if not self.spf or (self.spf.domain != domain):
            self.spf = record
            
    def add_dkim(self, record: DKIMRecord) -> None:
        """Add a DKIM record."""
        if not self.dkims or (self.dkims[-1].selector != record.selector):
            self.dkims.append(record)


def calculate_spoofability_score(result: DMARCAuditResult) -> tuple[float, list[str]]:
    """
    Calculate overall spoofability score (0-100).
    
    Returns:
        Tuple of (score, prioritized_fixes)
    """
    fixes = []
    base_score = 100.0
    
    # DMARC scoring (max -30 points)
    if result.dmarc:
        policy = result.dmarc.policy
        
        if policy == PolicyState.NONE:
            base_score -= 25
            fixes.append(("DMARC", "HIGH", 
                f"Enable DMARC with p=quarantine or p=reject. Current: {policy.value}"))
                
        elif policy == PolicyState.QUARANTINE:
            base_score -= 10
            
        elif policy == PolicyState.REJECT:
            base_score -= 2
            
        # Check alignment modes
        if result.dmarc.adkim == AlignmentMode.RELAXED:
            base_score -= 3
            fixes.append(("DMARC", "MEDIUM", 
                f"Use adkim=strict for tighter security"))
                
        if result.dmarc.aspf == AlignmentMode.RELAXED:
            base_score -= 2
            
        # Check reporting addresses
        if not result.dmarc.rua:
            base_score -= 5
            fixes.append(("DMARC", "MEDIUM", 
                f"Add rua=mailto:<address> for monitoring"))
                
    # SPF scoring (max -10 points)
    if result.spf:
        has_all = result.spf.has_all
        
        if not has_all:
            base_score -= 15
            fixes.append(("SPF", "HIGH", 
                f"Add -all to SPF record. Current parts: {len(result.spf.parts)}"))
                
        elif result.spf.all_type == "+all":
            base_score -= 8
            fixes.append(("SPF", "MEDIUM", 
                f"Change +all to -all for proper failover"))
                
    # DKIM scoring (max -15 points)
    dkim_issues = []
    
    if result.dkims:
        valid_count = sum(1 for d in result.dkims if d.is_valid)
        
        if not any(d.is_valid for d in result.dkims):
            base_score -= 15
            fixes.append(("DKIM", "HIGH", 
                f"Fix or regenerate DKIM keys. {len(result.dkims)} selectors checked."))
                
        elif valid_count < len(result.dkims):
            invalid = [d.selector for d in result.dkims if not d.is_valid]
            base_score -= 10
            fixes.append(("DKIM", "HIGH", 
                f"Fix invalid keys: {', '.join(invalid)}"))
                
        # Check key lengths
        short_keys = [d.selector for d in result.dkims 
                     if d.key_length and d.key_length < 128]
        
        if short_keys:
            base_score -= 5
            fixes.append(("DKIM", "LOW", 
                f"Consider regenerating keys with proper length: {', '.join(short_keys)}"))
                
    # Calculate final score (min 0)
    final_score = max(0.0, base_score)
    
    return round(final_score, 1), fixes


def format_report(result: DMARCAuditResult, 
                  score: float, 
                  fixes: list[tuple[str, str, str]]) -> str:
    """Format the audit report as a readable string."""
    lines = []
    
    # Header
    lines.append("=" * 60)
    lines.append(f"DMARC/SPF/DKIM Audit Report for: {result.domain}")
    lines.append(f"Timestamp: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 60)
    
    # Spoofability Score
    lines.append("")
    lines.append(f"SPOOFABILITY SCORE: {score}/100")
    
    if score >= 90:
        status = "GOOD"
    elif score >= 70:
        status = "FAIR"
    elif score >= 50:
        status = "NEEDS ATTENTION"
    else:
        status = "HIGH RISK"
        
    lines.append(f"Status: {status}")
    
    # DMARC Section
    if result.dmarc:
        lines.append("")
        lines.append("-" * 40)
        lines.append("DMARC RECORD")
        lines.append("-" * 40)
        
        policy_str = result.dmarc.policy.value.upper()
        lines.append(f"  Policy (p): {policy_str}")
        lines.append(f"  Subdomain Policy (sp): {result.dmarc.sp}")
        lines.append(f"  Percentage (pct): {result.dmarc.pct}")
        
        if result.dmarc.rua:
            lines.append(f"  Reporting Addresses (rua):")
            for addr in result.dmarc.rua:
                lines.append(f"    - {addr}")
                
        if result.dmarc.ruf:
            lines.append(f"  Forensic Addresses (ruf):")
            for addr in result.dmarc.ruf:
                lines.append(f"    - {addr}")
                
        alignment = f"{result.dmarc.adkim.value.upper()}/{result.dmarc.aspf.value.upper()}"
        lines.append(f"  Alignment: {alignment}")
        
    # SPF Section
    if result.spf:
        lines.append("")
        lines.append("-" * 40)
        lines.append("SPF RECORD")
        lines.append("-" * 40)
        
        has_all_str = f"{result.spf.all_type}" if result.spf.has_all else "(missing -all)"
        lines.append(f"  Has -all: {has_all_str}")
        lines.append(f"  Includes/Redirects: {result.spf.includes}/{result.spf.redirects}")
        
    # DKIM Section
    if result.dkims:
        lines.append("")
        lines.append("-" * 40)
        lines.append("DKIM RECORDS")
        lines.append("-" * 40)
        
        for dkim in result.dkims:
            status = "VALID" if dkim.is_valid else f"INVALID ({dkim.algorithm})"
            lines.append(f"  Selector '{dkim.selector}': {status}")
            
            if dkim.key_length:
                lines.append(f"    Key Length: {dkim.key_length} bytes")
                
            if dkim.issues:
                for issue in dkim.issues:
                    lines.append(f"    Issue: {issue}")
                    
    # Prioritized Fixes
    if fixes:
        lines.append("")
        lines.append("-" * 40)
        lines.append("PRIORITIZED FIXES")
        lines.append("-" * 40)
        
        for priority, category, fix in sorted(fixes, 
                                               key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x[1], 3)):
            marker = {0: "[HIGH]", 1: "[MEDIUM]", 2: "[LOW]"}.get(priority, "")
            lines.append(f"  {marker} {category}: {fix}")
            
    # Summary
    lines.append("")
    lines.append("=" * 60)
    lines.append("SUMMARY")
    lines.append("=" * 60)
    
    if score >= 90:
        summary = "Domain has strong email authentication posture."
    elif score >= 70:
        summary = "Domain is reasonably secure but has minor improvements needed."
    elif score >= 50:
        summary = "Domain requires attention to reduce spoofability risk."
    else:
        summary = "Domain is vulnerable to email spoofing attacks."
        
    lines.append(f"  {summary}")
    lines.append("")
    
    return "\n".join(lines)


def fetch_dns_records(domain: str, 
                      record_type: str = "TXT",
                      subdomain: Optional[str] = None) -> list[str]:
    """Fetch DNS TXT records for a domain.
    
    Uses standard library dns module if available, otherwise falls back to simple parsing.
    """
    try:
        import dns.resolver
        import dns.rdtypes.IN.TXT
        
        resolver = dns.resolver.Resolver()
        
        # Build query name
        if subdomain:
            query_name = f"{subdomain}.{domain}"
        else:
            query_name = domain
            
        records = []
        for rdata in resolver.resolve(query_name, record_type):
            if isinstance(rdata, dns.rdtypes.IN.TXT.TXT):
                # TXT records can be split across multiple packets
                text_parts = [str(x) for x in rdata.text]
                records.append(" ".join(text_parts))
                
        return records
        
    except ImportError:
        pass
    except Exception as e:
        print(f"DNS