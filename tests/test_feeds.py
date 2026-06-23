"""Tests for edge threat-feed enrichment + the datafeeds ingester.

NETWORK SAFETY: every test runs with offline=True or against a fabricated cache
in a tmp dir. No feed is ever fetched from the network here.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit import audit_domain, enrich_with_feeds  # noqa: E402
from dmarcaudit import feeds as feeds_mod  # noqa: E402
from dmarcaudit import datafeeds  # noqa: E402
from dmarcaudit.feeds import AbuseBlocklist  # noqa: E402


# --------------------------- AbuseBlocklist ------------------------------ #
def test_blocklist_has_ip():
    bl = AbuseBlocklist(ips=["198.51.100.5"])
    assert bl.has_ip("198.51.100.5") is True
    assert bl.has_ip("203.0.113.9") is False


def test_blocklist_has_domain_exact():
    bl = AbuseBlocklist(domains=["evil.example"])
    assert bl.has_domain("evil.example") is True
    assert bl.has_domain("good.example") is False


def test_blocklist_domain_parent_match():
    bl = AbuseBlocklist(domains=["evil.example"])
    assert bl.has_domain("sub.evil.example") is True


def test_blocklist_len():
    bl = AbuseBlocklist(ips=["1.2.3.4"], domains=["a.com", "b.com"])
    assert len(bl) == 3


def test_blocklist_add_text_scrapes_ips_and_domains():
    bl = AbuseBlocklist()
    bl.add_text("# comment\n203.0.113.7,malware\nbad-host.example online\n")
    assert bl.has_ip("203.0.113.7")
    assert bl.has_domain("bad-host.example")


def test_blocklist_case_insensitive_domain():
    bl = AbuseBlocklist(domains=["Evil.Example"])
    assert bl.has_domain("evil.example") is True


# --------------------------- enrichment ---------------------------------- #
def test_enrich_flags_authorized_abuse_ip():
    res = audit_domain("victim.example",
                       spf_record="v=spf1 ip4:198.51.100.5 -all",
                       dmarc_record="v=DMARC1; p=reject; rua=mailto:a@victim.example")
    bl = AbuseBlocklist(ips=["198.51.100.5"])
    enrich_with_feeds(res, bl)
    assert any(f.code == "SPF_AUTHORIZES_ABUSE_IP" and f.severity == "HIGH"
               for f in res.findings)


def test_enrich_flags_authorized_abuse_domain():
    res = audit_domain("victim.example",
                       spf_record="v=spf1 include:bad-provider.example -all",
                       dmarc_record="v=DMARC1; p=reject; rua=mailto:a@victim.example")
    bl = AbuseBlocklist(domains=["bad-provider.example"])
    enrich_with_feeds(res, bl)
    assert any(f.code == "SPF_AUTHORIZES_ABUSE_DOMAIN" for f in res.findings)


def test_enrich_no_false_positive_on_clean():
    res = audit_domain("clean.example",
                       spf_record="v=spf1 ip4:198.51.100.5 -all",
                       dmarc_record="v=DMARC1; p=reject; rua=mailto:a@clean.example")
    before = len(res.findings)
    enrich_with_feeds(res, AbuseBlocklist(ips=["10.0.0.1"]))
    assert len(res.findings) == before  # nothing matched -> nothing added


def test_enrich_resorts_findings():
    res = audit_domain("v.example", spf_record="v=spf1 ip4:198.51.100.5 ~all",
                       dmarc_record="v=DMARC1; p=reject; rua=mailto:a@v.example")
    enrich_with_feeds(res, AbuseBlocklist(ips=["198.51.100.5"]))
    from dmarcaudit import SEVERITY_ORDER
    ranks = [SEVERITY_ORDER[f.severity] for f in res.findings]
    assert ranks == sorted(ranks, reverse=True)


# --------------------------- datafeeds catalog --------------------------- #
def test_catalog_bundled_and_nonempty():
    cat = datafeeds.load_catalog()
    assert cat["feeds"], "bundled catalog should not be empty"


def test_catalog_has_abuse_feeds():
    ids = {f["id"] for f in datafeeds.list_feeds()}
    # at least one of the abuse feeds the enricher relies on must exist
    assert ids & set(feeds_mod.ABUSE_FEEDS)


def test_list_feeds_domain_filter():
    vuln = datafeeds.list_feeds(domain="vuln")
    assert vuln and all(f["domain"] == "vuln" for f in vuln)


def test_feeds_load_offline_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    bl = feeds_mod.load(offline=True)  # nothing cached -> empty, no network
    assert len(bl) == 0


def test_feeds_load_offline_with_fake_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    # fabricate a cached urlhaus feed entry
    feed_id = "urlhaus"
    (tmp_path / f"{feed_id}.data").write_text(
        json.dumps([{"url": "http://bad-host.example/x", "ip": "203.0.113.7"}]),
        encoding="utf-8")
    (tmp_path / f"{feed_id}.meta.json").write_text(
        json.dumps({"feed": feed_id, "fetched_at": 9e18, "format": "json"}),
        encoding="utf-8")
    bl = feeds_mod.load(feeds=[feed_id], offline=True)
    assert bl.has_ip("203.0.113.7")
    assert bl.has_domain("bad-host.example")


def test_snapshot_export_import_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "cache"))
    os.makedirs(tmp_path / "cache", exist_ok=True)
    (tmp_path / "cache" / "feodo-c2.data").write_text("1.2.3.4", encoding="utf-8")
    (tmp_path / "cache" / "feodo-c2.meta.json").write_text(
        json.dumps({"feed": "feodo-c2", "fetched_at": 1.0}), encoding="utf-8")
    arc = str(tmp_path / "snap.tar.gz")
    n = datafeeds.snapshot_export(arc)
    assert n == 1
    # import into a fresh cache dir
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "cache2"))
    os.makedirs(tmp_path / "cache2", exist_ok=True)
    m = datafeeds.snapshot_import(arc)
    assert m == 1


def test_datafeeds_list_cli(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    rc = datafeeds.main(["list"])
    assert rc == 0
    assert "cisa-kev" in capsys.readouterr().out


def test_get_offline_missing_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    import pytest
    with pytest.raises(FileNotFoundError):
        datafeeds.get("cisa-kev", offline=True)


if __name__ == "__main__":
    print("run via pytest (uses tmp_path / monkeypatch fixtures)")
