"""Deep parser + grading tests for dmarcaudit. No network, stdlib only."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit import (  # noqa: E402
    parse_spf, parse_dmarc, parse_dkim, grade, audit_domain, spf_hosts,
    SEVERITY_ORDER, TOOL_VERSION,
)

RSA2048 = ("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6f2qBNj"
           "811HK+iXkcVZ2RaaoAcgj8TPTokcPdMJnQPvjLpJtUc441mqtQCZNjc8F1x/G7nyRA4r"
           "+AnC/crjkLAEdJDUHROAZqc1UJJLr5FN8XwWIx4O+Zk0yw1rWgPsCwB/PwZDtLgL8YAVl"
           "RX+6ygxWjJlvy7QIka7HTcQL33Hh1XddasFdGOnixgLqRGFgImVGIRW09VerwV2xVLN7g"
           "ELNDGowZWBh5OdkUeLqi/c4eG2b+AiwcmuGR3G4u8sbyXY1oHNqo7lSicUx4cYSJWZJOX"
           "J5xDfaFv8bdd0wxyQmEyNsHsieaYpC/dhK5t/hoHB2GTqrF8fZBBuBG5S/QIDAQAB")
RSA512 = ("v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKW8aKnGpflynUWfpqSO"
          "UNbWjE3GEFsTIQ4CqidjPXJ+lsJilkHfRSIOk3pQ5R8azrfXZeDvahxoZSEDIqqK+NUCA"
          "wEAAQ==")


# --------------------------- SPF parser ---------------------------------- #
def test_spf_none_and_garbage():
    assert parse_spf(None)["present"] is False
    assert parse_spf("")["present"] is False
    assert parse_spf("v=spf2 foo")["present"] is False
    assert parse_spf("random text")["valid"] is False


def test_spf_quoted_record():
    spf = parse_spf('"v=spf1 -all"')
    assert spf["present"] is True
    assert spf["all"] == "-all"


def test_spf_case_insensitive():
    spf = parse_spf("V=SPF1 INCLUDE:x.com -ALL")
    assert spf["present"] is True
    assert spf["all"] == "-all"
    assert spf["lookups"] == 1


def test_spf_all_variants():
    for raw, expect in [("v=spf1 -all", "-all"), ("v=spf1 ~all", "~all"),
                        ("v=spf1 ?all", "?all"), ("v=spf1 +all", "+all"),
                        ("v=spf1 all", "+all")]:
        assert parse_spf(raw)["all"] == expect


def test_spf_no_all():
    spf = parse_spf("v=spf1 include:x.com")
    assert spf["all"] is None


def test_spf_lookup_counting():
    spf = parse_spf("v=spf1 a mx include:a.com include:b.com ip4:1.2.3.4 -all")
    # a + mx + 2 includes = 4 lookups; ip4 is not a lookup
    assert spf["lookups"] == 4


def test_spf_redirect_counts_as_lookup():
    spf = parse_spf("v=spf1 redirect=_spf.example.com")
    assert spf["redirect"] == "_spf.example.com"
    assert spf["lookups"] == 1


def test_spf_ip_mechanisms_not_lookups():
    spf = parse_spf("v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 -all")
    assert spf["lookups"] == 0


def test_spf_mechanisms_recorded():
    spf = parse_spf("v=spf1 include:a.com ip4:1.2.3.4 -all")
    assert "include:a.com" in spf["mechanisms"]
    assert "ip4:1.2.3.4" in spf["mechanisms"]


# --------------------------- DMARC parser -------------------------------- #
def test_dmarc_none_and_garbage():
    assert parse_dmarc(None)["present"] is False
    assert parse_dmarc("v=spf1 -all")["present"] is False
    assert parse_dmarc("")["present"] is False


def test_dmarc_tag_parsing():
    d = parse_dmarc("v=DMARC1; p=reject; sp=quarantine; pct=50; "
                    "rua=mailto:a@b.com; adkim=s; aspf=r")
    assert d["present"] is True
    assert d["tags"]["p"] == "reject"
    assert d["tags"]["sp"] == "quarantine"
    assert d["tags"]["pct"] == "50"
    assert d["tags"]["adkim"] == "s"
    assert d["tags"]["aspf"] == "r"
    assert d["tags"]["rua"] == "mailto:a@b.com"


def test_dmarc_quoted_and_spacing():
    d = parse_dmarc('"v=DMARC1;  p=quarantine ;  rua = mailto:x@y.com "')
    assert d["present"] is True
    assert d["tags"]["p"] == "quarantine"
    assert d["tags"]["rua"] == "mailto:x@y.com"


def test_dmarc_valid_flag():
    assert parse_dmarc("v=DMARC1; p=none")["valid"] is True


# --------------------------- DKIM parser --------------------------------- #
def test_dkim_none_and_garbage():
    assert parse_dkim(None)["present"] is False
    assert parse_dkim("")["present"] is False
    assert parse_dkim("just words")["present"] is False


def test_dkim_2048_bits():
    d = parse_dkim(RSA2048)
    assert d["present"] is True and d["valid"] is True
    assert d["key_bits"] == 2048


def test_dkim_512_weak():
    d = parse_dkim(RSA512)
    assert d["present"] is True
    assert d["key_bits"] == 512


def test_dkim_testing_flag_parsed():
    d = parse_dkim(RSA2048.replace("v=DKIM1;", "v=DKIM1; t=y;"))
    assert d["tags"].get("t") == "y"


def test_dkim_present_without_v():
    # a bare p= record (no v=DKIM1) should still be recognized as present
    d = parse_dkim("k=rsa; p=" + RSA2048.split("p=")[1])
    assert d["present"] is True


# --------------------------- grading ------------------------------------- #
def test_grade_returns_tuple():
    out = grade(parse_spf("v=spf1 -all"), parse_dmarc("v=DMARC1; p=reject"),
                parse_dkim(RSA2048))
    assert len(out) == 4
    letter, score, spoofable, findings = out
    assert letter in "ABCDF"
    assert 0 <= score <= 100
    assert isinstance(spoofable, bool)
    assert isinstance(findings, list)


def test_grade_passall_critical_present():
    _, _, spoof, findings = grade(parse_spf("v=spf1 +all"),
                                  parse_dmarc("v=DMARC1; p=reject"),
                                  parse_dkim(RSA2048))
    assert spoof is True
    assert any(f.code == "SPF_PASSALL" for f in findings)


def test_grade_softfail_finding():
    _, _, _, findings = grade(parse_spf("v=spf1 ~all"),
                              parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com"),
                              parse_dkim(RSA2048))
    assert any(f.code == "SPF_SOFTFAIL" and f.severity == "MEDIUM" for f in findings)


def test_grade_neutral_finding():
    _, _, _, findings = grade(parse_spf("v=spf1 ?all"),
                              parse_dmarc("v=DMARC1; p=reject"),
                              parse_dkim(RSA2048))
    assert any(f.code == "SPF_NEUTRAL" for f in findings)


def test_grade_dmarc_none_high():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=none"),
                              parse_dkim(RSA2048))
    codes = {f.code for f in findings}
    assert "DMARC_POLICY_NONE" in codes


def test_grade_quarantine_low():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:a@b.com"),
                              parse_dkim(RSA2048))
    assert any(f.code == "DMARC_QUARANTINE" and f.severity == "LOW" for f in findings)


def test_grade_partial_pct():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=reject; pct=25; rua=mailto:a@b.com"),
                              parse_dkim(RSA2048))
    assert any(f.code == "DMARC_PARTIAL_PCT" for f in findings)


def test_grade_subdomain_none():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com"),
                              parse_dkim(RSA2048))
    assert any(f.code == "DMARC_SUBDOMAIN_NONE" for f in findings)


def test_grade_no_rua():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=reject"),
                              parse_dkim(RSA2048))
    assert any(f.code == "DMARC_NO_RUA" for f in findings)


def test_grade_weak_dkim_critical():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com"),
                              parse_dkim(RSA512))
    assert any(f.code == "DKIM_WEAK_KEY" and f.severity == "CRITICAL" for f in findings)


def test_grade_missing_dkim_medium():
    _, _, _, findings = grade(parse_spf("v=spf1 -all"),
                              parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com"),
                              parse_dkim(None))
    assert any(f.code == "DKIM_MISSING" and f.severity == "MEDIUM" for f in findings)


def test_grade_too_many_lookups():
    spf = "v=spf1 " + " ".join(f"include:p{i}.com" for i in range(11)) + " -all"
    _, _, _, findings = grade(parse_spf(spf),
                              parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com"),
                              parse_dkim(RSA2048))
    assert any(f.code == "SPF_TOO_MANY_LOOKUPS" for f in findings)


def test_score_caps_at_100():
    _, score, _, _ = grade(parse_spf("v=spf1 -all"),
                           parse_dmarc("v=DMARC1; p=reject; sp=reject; adkim=s; "
                                       "aspf=s; pct=100; rua=mailto:a@b.com"),
                           parse_dkim(RSA2048))
    assert score <= 100


def test_spoofable_capped_grade():
    _, score, spoof, _ = grade(parse_spf("v=spf1 -all"),
                               parse_dmarc("v=DMARC1; p=none; rua=mailto:a@b.com"),
                               parse_dkim(RSA2048))
    assert spoof is True
    assert score <= 64


def test_hardened_not_spoofable():
    letter, score, spoof, _ = grade(
        parse_spf("v=spf1 include:_spf.google.com -all"),
        parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100"),
        parse_dkim(RSA2048))
    assert spoof is False
    assert score >= 70
    assert letter in ("A", "B", "C")


def test_severity_order_constants():
    assert SEVERITY_ORDER["CRITICAL"] > SEVERITY_ORDER["HIGH"]
    assert SEVERITY_ORDER["HIGH"] > SEVERITY_ORDER["MEDIUM"]
    assert SEVERITY_ORDER["LOW"] > SEVERITY_ORDER["INFO"]


# --------------------------- audit_domain + result ----------------------- #
def test_audit_result_worst_severity():
    res = audit_domain("x.com", spf_record="v=spf1 +all")
    assert res.worst_severity == "CRITICAL"


def test_audit_findings_sorted_worst_first():
    res = audit_domain("x.com", spf_record="v=spf1 +all",
                       dmarc_record="v=DMARC1; p=none")
    ranks = [SEVERITY_ORDER[f.severity] for f in res.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_audit_to_dict_findings_are_dicts():
    res = audit_domain("x.com", spf_record="v=spf1 +all")
    d = res.to_dict()
    assert all(isinstance(f, dict) for f in d["findings"])
    assert d["domain"] == "x.com"


def test_audit_default_domain_unknown():
    res = audit_domain(None, spf_record="v=spf1 -all")
    assert res.domain is None or res.domain == "unknown" or res.domain is None


# --------------------------- spf_hosts ----------------------------------- #
def test_spf_hosts_extracts_ips_and_domains():
    spf = parse_spf("v=spf1 ip4:198.51.100.5 ip4:203.0.113.0/24 "
                    "include:_spf.google.com include:sendgrid.net -all")
    hosts = spf_hosts(spf)
    assert "198.51.100.5" in hosts["ip4"]
    assert "203.0.113.0" in hosts["ip4"]
    assert "_spf.google.com" in hosts["domains"]
    assert "sendgrid.net" in hosts["domains"]


def test_spf_hosts_empty_for_no_spf():
    hosts = spf_hosts(parse_spf(None))
    assert hosts["ip4"] == [] and hosts["domains"] == []


def test_spf_hosts_redirect_domain():
    hosts = spf_hosts(parse_spf("v=spf1 redirect=_spf.example.com"))
    assert "_spf.example.com" in hosts["domains"]


def test_version_is_set():
    assert TOOL_VERSION and isinstance(TOOL_VERSION, str)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print(f"\n{len(fns)} parser tests passed")
