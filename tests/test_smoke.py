"""Smoke tests for DMARCAUDIT. No network. Run: python -m pytest tests/ -q
or simply: python tests/test_smoke.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit import (  # noqa: E402
    audit_domain, parse_spf, parse_dmarc, parse_dkim, grade,
    TOOL_NAME, TOOL_VERSION,
)
from dmarcaudit.cli import main, _render_html  # noqa: E402

GOOD_DKIM = ("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1Z8xQ2bF8"
             "vQ3kP9mYwRtJ0aLcVnB7eHsX4uYi2dZ5fGq1oWpTkLmN3rScDgHjFvBxUaEoIzPwQ7"
             "yMnRtVbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz"
             "QIDAQAB")


def test_meta():
    assert TOOL_NAME == "dmarcaudit"
    assert TOOL_VERSION


def test_parse_spf():
    spf = parse_spf("v=spf1 include:_spf.google.com mx -all")
    assert spf["present"] and spf["valid"]
    assert spf["all"] == "-all"
    assert spf["lookups"] == 2  # include + mx
    assert parse_spf(None)["present"] is False
    assert parse_spf("not an spf record")["present"] is False


def test_parse_dmarc():
    d = parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100")
    assert d["present"]
    assert d["tags"]["p"] == "reject"
    assert d["tags"]["pct"] == "100"
    assert parse_dmarc(None)["present"] is False


def test_parse_dkim_bits():
    d = parse_dkim(GOOD_DKIM)
    assert d["present"] and d["valid"]
    assert d["key_bits"] in (1024, 2048, 4096)


def test_passall_is_critical_and_spoofable():
    res = audit_domain("bad.com", spf_record="v=spf1 +all")
    assert res.spoofable is True
    assert any(f.code == "SPF_PASSALL" and f.severity == "CRITICAL"
               for f in res.findings)
    assert res.grade == "F"


def test_missing_everything():
    res = audit_domain("empty.com")
    assert res.spoofable is True
    codes = {f.code for f in res.findings}
    assert "DMARC_MISSING" in codes
    assert "SPF_MISSING" in codes


def test_hardened_domain_passes():
    res = audit_domain(
        "good.com",
        spf_record="v=spf1 include:_spf.google.com -all",
        dmarc_record="v=DMARC1; p=reject; rua=mailto:d@good.com; pct=100",
        dkim_record=GOOD_DKIM,
    )
    assert res.spoofable is False
    assert res.grade in ("A", "B", "C")
    assert res.score >= 70


def test_p_none_caps_grade():
    res = audit_domain(
        "monitor.com",
        spf_record="v=spf1 include:_spf.google.com -all",
        dmarc_record="v=DMARC1; p=none; rua=mailto:d@monitor.com",
        dkim_record=GOOD_DKIM,
    )
    # p=none => still spoofable => grade capped, exit nonzero
    assert res.spoofable is True
    assert res.score <= 64


def test_grade_function_signature():
    spf = parse_spf("v=spf1 -all")
    dmarc = parse_dmarc("v=DMARC1; p=reject")
    dkim = parse_dkim(GOOD_DKIM)
    letter, score, spoofable, findings = grade(spf, dmarc, dkim)
    assert letter in "ABCDF"
    assert 0 <= score <= 100
    assert isinstance(spoofable, bool)


def test_json_roundtrip():
    res = audit_domain("j.com", spf_record="v=spf1 -all")
    blob = json.dumps(res.to_dict())
    parsed = json.loads(blob)
    assert parsed["domain"] == "j.com"
    assert "findings" in parsed


def test_html_renders():
    res = audit_domain("h.com", spf_record="v=spf1 +all")
    out = _render_html(res)
    assert out.startswith("<!DOCTYPE html>")
    assert "<style>" in out
    assert "h.com" in out
    assert "SPF_PASSALL" in out


def test_cli_exit_codes():
    # spoofable -> exit 1
    rc = main(["audit", "--domain", "x.com", "--spf", "v=spf1 +all",
               "--format", "json"])
    assert rc == 1
    # hardened -> exit 0
    rc = main(["audit", "--domain", "g.com",
               "--spf", "v=spf1 include:_spf.google.com -all",
               "--dmarc", "v=DMARC1; p=reject; rua=mailto:d@g.com; pct=100",
               "--dkim", GOOD_DKIM, "--format", "json"])
    assert rc == 0


def test_cli_no_args_errors():
    try:
        main(["audit"])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("expected SystemExit for missing input")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print(f"PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {fn.__name__}: {exc}")
            raise
    print(f"\n{passed}/{len(fns)} tests passed")
