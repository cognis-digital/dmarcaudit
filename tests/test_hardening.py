"""Hardening tests: error paths, edge cases, and input validation.

These tests target the new guards added to core.py and cli.py.  All existing
tests in test_smoke.py must remain passing.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit.core import (  # noqa: E402
    audit_domain,
    parse_spf,
    parse_dmarc,
    parse_dkim,
    scan,
    to_json,
    AuditResult,
)
from dmarcaudit.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# core.py — edge-case inputs
# ---------------------------------------------------------------------------

def test_audit_domain_none_domain():
    """None or empty domain is coerced to 'unknown', not a crash."""
    res = audit_domain(None)  # type: ignore[arg-type]
    assert res.domain == "unknown"
    assert isinstance(res, AuditResult)


def test_audit_domain_empty_string():
    res = audit_domain("")
    assert res.domain == "unknown"


def test_audit_domain_whitespace_domain():
    res = audit_domain("   ")
    assert res.domain == "unknown"


def test_audit_domain_non_string_records_coerced():
    """Non-string record args (e.g. an integer) must not raise — treated as absent."""
    res = audit_domain("example.com", spf_record=12345, dmarc_record=[], dkim_record={})  # type: ignore[arg-type]
    assert res.spf["present"] is False
    assert res.dmarc["present"] is False
    assert res.dkim["present"] is False


def test_audit_domain_empty_record_strings():
    """Empty string records are equivalent to absent."""
    res = audit_domain("example.com", spf_record="", dmarc_record="", dkim_record="")
    assert res.spf["present"] is False
    assert res.dmarc["present"] is False


def test_parse_spf_empty_string():
    out = parse_spf("")
    assert out["present"] is False


def test_parse_dmarc_empty_string():
    out = parse_dmarc("")
    assert out["present"] is False


def test_parse_dkim_empty_string():
    out = parse_dkim("")
    assert out["present"] is False


def test_worst_severity_unknown_code():
    """worst_severity must not KeyError on an unrecognised severity string."""
    res = audit_domain("safe.com", spf_record="v=spf1 -all",
                       dmarc_record="v=DMARC1; p=reject")
    # Inject a finding with an unrecognised severity via dict round-trip hack.
    res.findings.append(type("F", (), {
        "severity": "UNKNOWN", "record": "X", "code": "X",
        "message": "x", "recommendation": ""
    })())
    # Should not raise.
    sev = res.worst_severity
    assert sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")


# ---------------------------------------------------------------------------
# core.py — scan() / to_json() aliases
# ---------------------------------------------------------------------------

def test_scan_alias():
    """scan() is a public alias for audit_domain()."""
    res = scan("example.com", spf_record="v=spf1 -all")
    assert isinstance(res, AuditResult)
    assert res.domain == "example.com"


def test_to_json_alias():
    """to_json() returns valid JSON with expected keys."""
    res = audit_domain("j2.com", spf_record="v=spf1 -all")
    blob = to_json(res)
    parsed = json.loads(blob)
    assert parsed["domain"] == "j2.com"
    assert "findings" in parsed
    assert "grade" in parsed


# ---------------------------------------------------------------------------
# cli.py — missing / malformed input file → exit 2
# ---------------------------------------------------------------------------

def test_cli_missing_input_file():
    """--input with a non-existent file must exit 2."""
    rc = main(["audit", "--input", "/nonexistent/path/records.json"])
    assert rc == 2


def test_cli_malformed_json_file():
    """--input pointing at a file with invalid JSON must exit 2."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False, encoding="utf-8") as fh:
        fh.write("this is not json {{{")
        tmpname = fh.name
    try:
        rc = main(["audit", "--input", tmpname])
        assert rc == 2
    finally:
        os.unlink(tmpname)


def test_cli_json_array_not_object():
    """--input JSON must be an object; a top-level array should exit 2."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False, encoding="utf-8") as fh:
        fh.write('["not", "an", "object"]')
        tmpname = fh.name
    try:
        rc = main(["audit", "--input", tmpname])
        assert rc == 2
    finally:
        os.unlink(tmpname)


def test_cli_json_field_wrong_type():
    """--input JSON with a non-string spf field must exit 2."""
    payload = {"domain": "x.com", "spf": 12345}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False, encoding="utf-8") as fh:
        json.dump(payload, fh)
        tmpname = fh.name
    try:
        rc = main(["audit", "--input", tmpname])
        assert rc == 2
    finally:
        os.unlink(tmpname)


def test_cli_valid_json_file_succeeds():
    """A well-formed input JSON file must not return exit 2."""
    payload = {
        "domain": "ok.com",
        "spf": "v=spf1 -all",
        "dmarc": "v=DMARC1; p=reject; rua=mailto:d@ok.com",
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False, encoding="utf-8") as fh:
        json.dump(payload, fh)
        tmpname = fh.name
    try:
        rc = main(["audit", "--input", tmpname, "--format", "json"])
        assert rc != 2  # 0 or 1 depending on posture — not an I/O error
    finally:
        os.unlink(tmpname)
