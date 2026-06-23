"""Tests for the authorization-gated, read-only ACTIVE mode.

NETWORK SAFETY: these tests never touch a real external host. They exercise the
authorization gate, the allowlist, the rate limiter, and the DNS TXT
encode/parse round-trip in-memory, and use an injected transport (or a local
UDP socket bound to 127.0.0.1) — never a public resolver.
"""
import os
import socket
import struct
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmarcaudit.active import (  # noqa: E402
    Allowlist, RateLimiter, ActiveResolver, AuthorizationError, NotAllowed,
    build_txt_query, parse_txt_response, _encode_qname, _decode_txt_rdata,
)


# --------------------------- Allowlist ----------------------------------- #
def test_allowlist_empty_permits_nothing():
    al = Allowlist()
    assert len(al) == 0
    assert al.permits("example.com") is False


def test_allowlist_exact_match():
    al = Allowlist.from_iter(["example.com"])
    assert al.permits("example.com") is True


def test_allowlist_strips_dmarc_prefix():
    al = Allowlist.from_iter(["example.com"])
    assert al.permits("_dmarc.example.com") is True


def test_allowlist_strips_domainkey_prefix():
    al = Allowlist.from_iter(["example.com"])
    assert al.permits("selector1._domainkey.example.com") is True


def test_allowlist_subdomain_matches_parent():
    al = Allowlist.from_iter(["example.com"])
    assert al.permits("mail.example.com") is True


def test_allowlist_rejects_unrelated():
    al = Allowlist.from_iter(["example.com"])
    assert al.permits("evil.com") is False
    assert al.permits("notexample.com") is False


def test_allowlist_case_and_trailing_dot():
    al = Allowlist.from_iter(["Example.COM."])
    assert al.permits("example.com") is True


def test_allowlist_from_env(monkeypatch):
    monkeypatch.setenv("DMARCAUDIT_ALLOW", "a.com, b.com; c.com")
    al = Allowlist.from_env()
    assert al.permits("a.com") and al.permits("b.com") and al.permits("c.com")
    assert al.permits("d.com") is False


# --------------------------- RateLimiter --------------------------------- #
def test_rate_limiter_allows_burst():
    rl = RateLimiter(rate=3.0)
    slept = []
    rl._sleep = lambda s: slept.append(s)
    for _ in range(3):
        rl.acquire()
    assert slept == []  # burst of 3 with no waiting


def test_rate_limiter_throttles_beyond_burst():
    clock = [0.0]
    rl = RateLimiter(rate=2.0)
    rl._clock = lambda: clock[0]
    waited = []
    rl._sleep = lambda s: waited.append(s)
    rl._tokens = 2.0
    rl.acquire(); rl.acquire()  # drain burst
    rl.acquire()                # must wait ~0.5s at 2/s
    assert waited and waited[0] > 0


# --------------------------- gate enforcement ---------------------------- #
def test_active_requires_authorized():
    r = ActiveResolver(authorized=False,
                       allowlist=Allowlist.from_iter(["example.com"]))
    with pytest.raises(AuthorizationError):
        r.txt("example.com")


def test_active_requires_nonempty_allowlist():
    r = ActiveResolver(authorized=True, allowlist=Allowlist())
    with pytest.raises(NotAllowed):
        r.txt("example.com")


def test_active_rejects_offlist_target():
    r = ActiveResolver(authorized=True,
                       allowlist=Allowlist.from_iter(["example.com"]))
    with pytest.raises(NotAllowed):
        r.txt("evil.com")


def test_active_allows_listed_target_via_transport():
    r = ActiveResolver(authorized=True,
                       allowlist=Allowlist.from_iter(["example.com"]))
    r._transport = lambda name: ["v=spf1 -all"]
    assert r.txt("example.com") == ["v=spf1 -all"]


def test_fetch_records_uses_transport_only_for_allowed():
    answers = {
        "example.com": ["v=spf1 include:_spf.google.com -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@example.com"],
        "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=ABC"],
    }
    r = ActiveResolver(authorized=True,
                       allowlist=Allowlist.from_iter(["example.com"]))
    r._transport = lambda name: answers.get(name.rstrip("."), [])
    rec = r.fetch_records("example.com")
    assert rec["domain"] == "example.com"
    assert rec["spf"].startswith("v=spf1")
    assert rec["dmarc"].startswith("v=DMARC1")
    assert rec["dkim"].startswith("v=DKIM1")


def test_fetch_records_blocked_when_unauthorized():
    r = ActiveResolver(authorized=False,
                       allowlist=Allowlist.from_iter(["example.com"]))
    with pytest.raises(AuthorizationError):
        r.fetch_records("example.com")


# --------------------------- DNS wire round-trip ------------------------- #
def test_encode_qname():
    out = _encode_qname("example.com")
    assert out == b"\x07example\x03com\x00"


def test_build_txt_query_structure():
    pkt = build_txt_query("example.com", txid=0x1234)
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", pkt[:12])
    assert txid == 0x1234
    assert qd == 1 and an == 0
    # question ends with QTYPE=16 (TXT), QCLASS=1 (IN)
    qtype, qclass = struct.unpack(">HH", pkt[-4:])
    assert qtype == 16 and qclass == 1


def test_decode_txt_rdata():
    rdata = bytes([5]) + b"hello" + bytes([5]) + b"world"
    assert _decode_txt_rdata(rdata) == "helloworld"


def _build_response(txid, qname, txt):
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    q = _encode_qname(qname) + struct.pack(">HH", 16, 1)
    txt_b = txt.encode()
    rdata = bytes([len(txt_b)]) + txt_b
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata
    return header + q + ans


def test_parse_txt_response_roundtrip():
    pkt = _build_response(0xABCD, "example.com", "v=spf1 -all")
    answers = parse_txt_response(pkt)
    assert answers == ["v=spf1 -all"]


def test_parse_txt_response_empty_on_truncated():
    assert parse_txt_response(b"\x00\x01") == []


def test_local_udp_resolver_127_0_0_1():
    """End-to-end over a UDP socket bound to localhost — never an external host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def serve():
        data, addr = sock.recvfrom(4096)
        txid = struct.unpack(">H", data[:2])[0]
        sock.sendto(_build_response(txid, "example.com", "v=spf1 ip4:127.0.0.1 -all"), addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.05)
    r = ActiveResolver(authorized=True,
                       allowlist=Allowlist.from_iter(["example.com"]),
                       resolver="127.0.0.1", port=port, timeout=2.0)
    answers = r.txt("example.com")
    sock.close()
    assert answers == ["v=spf1 ip4:127.0.0.1 -all"]


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and "monkeypatch" not in v.__code__.co_varnames]
    passed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print("PASS", fn.__name__)
        except Exception:
            print("FAIL", fn.__name__)
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} active tests passed (run via pytest for full set)")
