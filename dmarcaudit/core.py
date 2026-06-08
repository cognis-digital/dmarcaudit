"""Core engine for DMARCAUDIT.

Parses SPF, DMARC and DKIM TXT records (the exact strings you'd pull with
`dig TXT`) and grades the domain's resistance to email spoofing. No network is
performed here: the caller supplies record strings (from a JSON input file or a
prior DNS dump), so the tool is fully offline and testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

# Severity weights: higher = worse. CRITICAL findings mean the domain is
# trivially spoofable.
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    severity: str          # CRITICAL/HIGH/MEDIUM/LOW/INFO
    record: str            # SPF / DKIM / DMARC / GENERAL
    code: str              # short machine code
    message: str           # human explanation
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditResult:
    domain: str
    grade: str = "F"
    score: int = 0
    spoofable: bool = True
    spf: dict = field(default_factory=dict)
    dmarc: dict = field(default_factory=dict)
    dkim: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() if isinstance(f, Finding) else f
                         for f in self.findings]
        return d

    @property
    def worst_severity(self) -> str:
        worst = "INFO"
        for f in self.findings:
            if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]:
                worst = f.severity
        return worst


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def parse_spf(record: Optional[str]) -> dict:
    """Parse an SPF TXT record into structured mechanisms."""
    out = {"present": False, "raw": record, "all": None, "mechanisms": [],
           "lookups": 0, "redirect": None, "valid": False}
    if not record:
        return out
    record = record.strip().strip('"')
    if not record.lower().startswith("v=spf1"):
        return out
    out["present"] = True
    out["valid"] = True
    tokens = record.split()[1:]
    # Mechanisms that trigger a DNS lookup (RFC 7208 §4.6.4, limit 10).
    for tok in tokens:
        low = tok.lower()
        if low in ("+all", "-all", "~all", "?all", "all"):
            out["all"] = "+all" if low == "all" else low
            continue
        if low.startswith("redirect="):
            out["redirect"] = tok.split("=", 1)[1]
            out["lookups"] += 1
            continue
        out["mechanisms"].append(tok)
        if low.startswith(("include:", "exists:")) or low in ("a", "mx", "ptr") \
                or low.startswith(("a:", "mx:", "a/", "mx/")):
            out["lookups"] += 1
    return out


def parse_dmarc(record: Optional[str]) -> dict:
    """Parse a DMARC TXT record (_dmarc.<domain>) into a tag dict."""
    out = {"present": False, "raw": record, "tags": {}, "valid": False}
    if not record:
        return out
    record = record.strip().strip('"')
    if not record.lower().startswith("v=dmarc1"):
        return out
    out["present"] = True
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out["tags"][k.strip().lower()] = v.strip()
    out["valid"] = out["tags"].get("v", "").lower() == "dmarc1" or \
        record.lower().startswith("v=dmarc1")
    return out


def parse_dkim(record: Optional[str]) -> dict:
    """Parse a DKIM public-key TXT record (<selector>._domainkey.<domain>)."""
    out = {"present": False, "raw": record, "tags": {}, "valid": False,
           "key_bits": None}
    if not record:
        return out
    record = record.strip().strip('"')
    low = record.lower()
    if "p=" not in low and "v=dkim1" not in low:
        return out
    out["present"] = True
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out["tags"][k.strip().lower()] = v.strip()
    pub = out["tags"].get("p", "")
    out["valid"] = bool(pub)
    if pub:
        # Estimate RSA modulus size from base64 length of the SubjectPublicKeyInfo.
        # ~ (b64_len * 3/4) bytes of DER; RSA-1024 SPKI ~162 bytes, RSA-2048 ~294.
        der_len = int(len(re.sub(r"\s+", "", pub)) * 3 / 4)
        if der_len >= 380:
            out["key_bits"] = 4096
        elif der_len >= 250:
            out["key_bits"] = 2048
        elif der_len >= 120:
            out["key_bits"] = 1024
        else:
            out["key_bits"] = 512
    return out


# --------------------------------------------------------------------------- #
# Grading engine
# --------------------------------------------------------------------------- #
def _grade_spf(spf: dict, findings: list) -> int:
    pts = 0
    if not spf.get("present"):
        findings.append(Finding(
            "HIGH", "SPF", "SPF_MISSING",
            "No SPF record found. Receivers cannot verify which hosts may send "
            "mail for this domain.",
            "Publish a TXT record: v=spf1 include:<your-provider> -all"))
        return pts
    pts += 20
    allmech = spf.get("all")
    if allmech == "-all":
        pts += 20
    elif allmech == "~all":
        pts += 12
        findings.append(Finding(
            "MEDIUM", "SPF", "SPF_SOFTFAIL",
            "SPF ends in ~all (softfail). Unauthorized senders are flagged but "
            "not rejected.",
            "Move to -all (hardfail) once you have confirmed all legitimate "
            "senders are listed."))
    elif allmech in ("+all", "all"):
        findings.append(Finding(
            "CRITICAL", "SPF", "SPF_PASSALL",
            "SPF ends in +all — ANY host on the Internet passes SPF for this "
            "domain. The domain is trivially spoofable.",
            "Replace +all with -all immediately."))
    elif allmech == "?all":
        pts += 4
        findings.append(Finding(
            "HIGH", "SPF", "SPF_NEUTRAL",
            "SPF ends in ?all (neutral) — provides no protection.",
            "Use -all (hardfail)."))
    else:
        findings.append(Finding(
            "MEDIUM", "SPF", "SPF_NO_ALL",
            "SPF has no 'all' mechanism; default is neutral (?all).",
            "Append -all to the SPF record."))
    if spf.get("lookups", 0) > 10:
        findings.append(Finding(
            "HIGH", "SPF", "SPF_TOO_MANY_LOOKUPS",
            f"SPF requires {spf['lookups']} DNS lookups (RFC 7208 limit is 10). "
            "Receivers will return permerror and may ignore SPF entirely.",
            "Flatten includes or remove unused providers to stay <=10 lookups."))
        pts -= 10
    return max(pts, 0)


def _grade_dmarc(dmarc: dict, findings: list) -> int:
    pts = 0
    if not dmarc.get("present"):
        findings.append(Finding(
            "CRITICAL", "DMARC", "DMARC_MISSING",
            "No DMARC record at _dmarc.<domain>. Without DMARC, SPF/DKIM "
            "failures are not enforced and the domain can be spoofed in the "
            "visible From: header.",
            "Publish: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>"))
        return pts
    pts += 15
    tags = dmarc["tags"]
    policy = tags.get("p", "none").lower()
    if policy == "reject":
        pts += 25
    elif policy == "quarantine":
        pts += 15
        findings.append(Finding(
            "LOW", "DMARC", "DMARC_QUARANTINE",
            "DMARC policy is p=quarantine. Spoofed mail is sent to spam rather "
            "than rejected.",
            "Move to p=reject after confirming reports are clean."))
    else:
        findings.append(Finding(
            "HIGH", "DMARC", "DMARC_POLICY_NONE",
            "DMARC policy is p=none (monitor only). Spoofed mail is still "
            "delivered to inboxes.",
            "Tighten to p=quarantine then p=reject."))
    pct = tags.get("pct")
    if pct is not None:
        try:
            if int(pct) < 100:
                findings.append(Finding(
                    "MEDIUM", "DMARC", "DMARC_PARTIAL_PCT",
                    f"DMARC pct={pct} — policy applies to only {pct}% of mail.",
                    "Set pct=100 for full enforcement."))
                pts -= 5
        except ValueError:
            pass
    sp = tags.get("sp")
    if sp and sp.lower() == "none" and policy != "none":
        findings.append(Finding(
            "MEDIUM", "DMARC", "DMARC_SUBDOMAIN_NONE",
            "Subdomain policy sp=none weakens protection for subdomains, a "
            "common spoofing vector.",
            "Remove sp=none or set sp=reject."))
        pts -= 5
    if not tags.get("rua"):
        findings.append(Finding(
            "LOW", "DMARC", "DMARC_NO_RUA",
            "No aggregate report address (rua). You are blind to spoofing "
            "attempts and authentication failures.",
            "Add rua=mailto:dmarc-reports@<domain>."))
    aspf = tags.get("aspf", "r").lower()
    adkim = tags.get("adkim", "r").lower()
    if aspf == "s" or adkim == "s":
        pts += 3  # strict alignment is stronger
    return max(pts, 0)


def _grade_dkim(dkim: dict, findings: list) -> int:
    pts = 0
    if not dkim.get("present"):
        findings.append(Finding(
            "MEDIUM", "DKIM", "DKIM_MISSING",
            "No DKIM record found for the supplied selector. DKIM provides a "
            "cryptographic signature that survives forwarding (unlike SPF).",
            "Enable DKIM signing at your mail provider and publish the public "
            "key at <selector>._domainkey.<domain>."))
        return pts
    pts += 15
    bits = dkim.get("key_bits")
    if bits is not None:
        if bits < 1024:
            findings.append(Finding(
                "CRITICAL", "DKIM", "DKIM_WEAK_KEY",
                f"DKIM key appears to be {bits}-bit — well below modern "
                "standards and forgeable.",
                "Rotate to a 2048-bit RSA key."))
        elif bits < 2048:
            findings.append(Finding(
                "MEDIUM", "DKIM", "DKIM_1024_KEY",
                "DKIM key is ~1024-bit. Acceptable but deprecated.",
                "Rotate to a 2048-bit RSA key."))
        else:
            pts += 5
    if dkim["tags"].get("t", "").lower().find("y") >= 0:
        findings.append(Finding(
            "LOW", "DKIM", "DKIM_TESTING",
            "DKIM record is in testing mode (t=y); receivers may ignore "
            "signature failures.",
            "Remove t=y once signing is verified."))
    return pts


def grade(spf: dict, dmarc: dict, dkim: dict) -> tuple:
    """Return (letter_grade, score_0_100, spoofable_bool, findings)."""
    findings: list = []
    score = 0
    score += _grade_spf(spf, findings)      # up to ~40
    score += _grade_dmarc(dmarc, findings)  # up to ~46
    score += _grade_dkim(dkim, findings)    # up to ~20
    score = min(score, 100)

    # A domain is "spoofable" if DMARC won't reject/quarantine OR SPF passes all.
    dmarc_policy = dmarc.get("tags", {}).get("p", "none").lower() \
        if dmarc.get("present") else "none"
    spf_all = spf.get("all")
    enforced = dmarc.get("present") and dmarc_policy in ("quarantine", "reject")
    spoofable = (not enforced) or spf_all in ("+all", "all")

    if spoofable:
        # Cap the grade — an enforceable policy is required for a passing grade.
        score = min(score, 64)

    if score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 60:
        letter = "D"
    else:
        letter = "F"
    return letter, score, spoofable, findings


def audit_domain(domain: str, spf_record=None, dmarc_record=None,
                 dkim_record=None) -> AuditResult:
    """Run a full audit given raw DNS TXT record strings."""
    spf = parse_spf(spf_record)
    dmarc = parse_dmarc(dmarc_record)
    dkim = parse_dkim(dkim_record)
    letter, score, spoofable, findings = grade(spf, dmarc, dkim)
    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    return AuditResult(domain=domain, grade=letter, score=score,
                       spoofable=spoofable, spf=spf, dmarc=dmarc, dkim=dkim,
                       findings=findings)
