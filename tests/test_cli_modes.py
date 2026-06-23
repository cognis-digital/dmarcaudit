"""CLI integration tests: scan/to_json helpers, active mode wiring, enrich flag,
and all output formats. No network — active mode uses fixtures/127.0.0.1 only.
"""
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit import scan, to_json, audit_domain  # noqa: E402
from dmarcaudit.cli import main, _render_table, _render_html, _render_sarif  # noqa: E402
from dmarcaudit.active import _encode_qname  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "03-spf-passall", "records.json")


# --------------------------- scan() / to_json() -------------------------- #
def test_scan_from_file():
    res = scan(DEMO)
    assert res.domain == "legacy-mailer.example"
    assert res.spoofable is True


def test_scan_from_json_string():
    res = scan('{"domain": "j.com", "spf": "v=spf1 +all"}')
    assert res.domain == "j.com"
    assert res.spoofable is True


def test_scan_from_domain_label():
    res = scan("bare.com", spf="v=spf1 -all",
               dmarc="v=DMARC1; p=reject; rua=mailto:a@bare.com")
    assert res.domain == "bare.com"


def test_to_json_roundtrip():
    blob = to_json(audit_domain("x.com", spf_record="v=spf1 +all"))
    parsed = json.loads(blob)
    assert parsed["domain"] == "x.com"
    assert parsed["spoofable"] is True


def test_to_json_accepts_dict():
    d = audit_domain("x.com", spf_record="v=spf1 -all").to_dict()
    assert json.loads(to_json(d))["domain"] == "x.com"


# --------------------------- output formats ------------------------------ #
def test_render_table_contains_grade():
    res = audit_domain("t.com", spf_record="v=spf1 +all")
    txt = _render_table(res)
    assert "DMARCAUDIT" in txt and "Grade" in txt and "t.com" in txt


def test_render_html_doctype():
    res = audit_domain("h.com", spf_record="v=spf1 +all")
    out = _render_html(res)
    assert out.startswith("<!DOCTYPE html>") and "SPF_PASSALL" in out


def test_render_sarif_valid():
    res = audit_domain("s.com", spf_record="v=spf1 +all")
    log = json.loads(_render_sarif(res))
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "dmarcaudit"


def test_cli_all_formats_run():
    for fmt in ("table", "json", "html", "sarif"):
        rc = main(["audit", "--domain", "x.com", "--spf", "v=spf1 +all",
                   "--format", fmt])
        assert rc == 1, fmt


def test_cli_writes_output_file(tmp_path):
    out = tmp_path / "r.json"
    rc = main(["audit", "--domain", "x.com", "--spf", "v=spf1 -all",
               "--dmarc", "v=DMARC1; p=reject; rua=mailto:a@x.com",
               "--format", "json", "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["domain"] == "x.com"


# --------------------------- active mode via CLI ------------------------- #
def _serve_once(sock, answers):
    data, addr = sock.recvfrom(4096)
    # extract qname to pick the right answer
    off, labels = 12, []
    while data[off] != 0:
        n = data[off]
        labels.append(data[off + 1:off + 1 + n].decode())
        off += 1 + n
    qname = ".".join(labels)
    txid = struct.unpack(">H", data[:2])[0]
    txt = answers.get(qname, "")
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1 if txt else 0, 0, 0)
    q = _encode_qname(qname) + struct.pack(">HH", 16, 1)
    pkt = header + q
    if txt:
        tb = txt.encode()
        rd = bytes([len(tb)]) + tb
        pkt += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rd)) + rd
    sock.sendto(pkt, addr)


def test_cli_active_requires_authorized():
    rc = main(["audit", "--active", "--domain", "example.com",
               "--allow", "example.com", "--format", "json"])
    assert rc == 2  # not authorized -> error exit


def test_cli_active_requires_allowlist():
    rc = main(["audit", "--active", "--authorized", "--domain", "example.com",
               "--format", "json"])
    assert rc == 2  # no allowlist -> error


def test_cli_active_offlist_target():
    rc = main(["audit", "--active", "--authorized", "--domain", "evil.com",
               "--allow", "example.com", "--resolver", "127.0.0.1",
               "--format", "json"])
    assert rc == 2  # target not on allowlist


def test_cli_active_localhost_resolver_end_to_end():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    answers = {
        "example.com": "v=spf1 +all",
        "_dmarc.example.com": "v=DMARC1; p=none",
    }
    # serve a few queries (spf, dmarc, dkim). DKIM has no answer -> empty reply.
    def loop():
        sock.settimeout(3.0)
        for _ in range(3):
            try:
                _serve_once(sock, answers)
            except (socket.timeout, OSError):
                break
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    time.sleep(0.05)
    try:
        rc = main(["audit", "--active", "--authorized", "--domain", "example.com",
                   "--allow", "example.com", "--resolver", "127.0.0.1",
                   "--port", str(port),
                   "--rate", "100", "--format", "json"])
    finally:
        sock.close()
        t.join(timeout=1.0)
    # +all + p=none => spoofable => exit 1
    assert rc == 1


# --------------------------- enrich flag (offline) ----------------------- #
def test_cli_enrich_offline_no_cache(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    rc = main(["audit", "--domain", "x.com", "--spf", "v=spf1 ip4:1.2.3.4 -all",
               "--dmarc", "v=DMARC1; p=reject; rua=mailto:a@x.com",
               "--enrich", "--format", "json"])
    # no feeds cached -> note printed, audit still completes (exit 0, hardened)
    assert rc == 0
    assert "no abuse feeds cached" in capsys.readouterr().err


def test_cli_enrich_with_fake_cache_flags_ip(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    (tmp_path / "urlhaus.data").write_text(
        json.dumps([{"ip": "198.51.100.5"}]), encoding="utf-8")
    (tmp_path / "urlhaus.meta.json").write_text(
        json.dumps({"feed": "urlhaus", "fetched_at": 9e18, "format": "json"}),
        encoding="utf-8")
    rc = main(["audit", "--domain", "x.com",
               "--spf", "v=spf1 ip4:198.51.100.5 -all",
               "--dmarc", "v=DMARC1; p=reject; rua=mailto:a@x.com",
               "--enrich", "--format", "json"])
    out = capsys.readouterr().out
    assert "SPF_AUTHORIZES_ABUSE_IP" in out
    assert rc == 1  # HIGH finding => non-zero exit


if __name__ == "__main__":
    print("run via pytest (uses tmp_path/monkeypatch fixtures + sockets)")
