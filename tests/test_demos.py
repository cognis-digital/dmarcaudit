"""Tests over the demos/ corpus and the SARIF exporter.

Each demo must (a) load as valid input, (b) audit cleanly, and (c) produce the
finding codes its SCENARIO promises. This is the regression net that keeps the
demo narratives honest.  No network. Run: python -m pytest tests/ -q
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit.cli import main, _render_sarif  # noqa: E402
from dmarcaudit.core import audit_domain  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")

# Demo folder -> (expected finding codes present, spoofable, expected CLI exit)
EXPECTED = {
    "01-basic": ({"DMARC_POLICY_NONE", "SPF_SOFTFAIL", "DKIM_1024_KEY"}, True, 1),
    "02-hardened-pass": (set(), False, 0),
    "03-spf-passall": ({"SPF_PASSALL", "DMARC_POLICY_NONE", "DKIM_MISSING"}, True, 1),
    "04-spf-too-many-lookups": ({"SPF_TOO_MANY_LOOKUPS"}, False, 1),
    "05-dkim-weak-key": ({"DKIM_WEAK_KEY"}, False, 1),
    "06-partial-rollout": (
        {"DMARC_PARTIAL_PCT", "DMARC_SUBDOMAIN_NONE", "SPF_SOFTFAIL"}, False, 0),
    "07-parked-domain": ({"DKIM_MISSING"}, False, 0),
    "08-subdomain-takeover-vector": ({"DMARC_SUBDOMAIN_NONE"}, False, 0),
}


def _records(folder):
    with open(os.path.join(DEMOS, folder, "records.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_all_demo_folders_present():
    found = {d for d in os.listdir(DEMOS)
             if os.path.isdir(os.path.join(DEMOS, d))}
    assert set(EXPECTED) <= found, f"missing demo folders: {set(EXPECTED) - found}"


def test_each_demo_has_records_and_scenario():
    for folder in EXPECTED:
        d = os.path.join(DEMOS, folder)
        assert os.path.isfile(os.path.join(d, "records.json")), folder
        assert os.path.isfile(os.path.join(d, "SCENARIO.md")), folder


def test_each_demo_fires_expected_findings():
    for folder, (codes, spoofable, _exit) in EXPECTED.items():
        rec = _records(folder)
        res = audit_domain(rec.get("domain"), rec.get("spf"),
                           rec.get("dmarc"), rec.get("dkim"))
        got = {f.code for f in res.findings}
        assert codes <= got, f"{folder}: expected {codes} within {got}"
        assert res.spoofable is spoofable, f"{folder}: spoofable mismatch"


def test_each_demo_cli_exit_code():
    for folder, (_codes, _spoof, expected_exit) in EXPECTED.items():
        path = os.path.join(DEMOS, folder, "records.json")
        rc = main(["audit", "--input", path, "--format", "json"])
        assert rc == expected_exit, f"{folder}: exit {rc} != {expected_exit}"


def test_sarif_is_valid_2_1_0():
    rec = _records("03-spf-passall")
    res = audit_domain(rec["domain"], rec.get("spf"), rec.get("dmarc"),
                       rec.get("dkim"))
    log = json.loads(_render_sarif(res))
    assert log["version"] == "2.1.0"
    assert log["runs"]
    run = log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "dmarcaudit"
    # Every result's ruleId must resolve to a defined rule.
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids, "no rules emitted"
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in ("error", "warning", "note")
        assert result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # Run-level summary carries grade/score/spoofable.
    props = run["properties"]
    assert props["domain"] == res.domain
    assert props["grade"] == res.grade
    assert isinstance(props["spoofable"], bool)


def test_sarif_security_severity_levels():
    res = audit_domain("crit.example", spf_record="v=spf1 +all")
    log = json.loads(_render_sarif(res))
    rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
    passall = rules["SPF_PASSALL"]
    assert passall["defaultConfiguration"]["level"] == "error"
    assert float(passall["properties"]["security-severity"]) >= 9.0


def test_cli_sarif_format_runs():
    rc = main(["audit", "--domain", "x.example", "--spf", "v=spf1 +all",
               "--format", "sarif"])
    assert rc == 1


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print(f"\n{len(fns)} tests passed")
