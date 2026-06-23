"""Optional ACTIVE mode for dmarcaudit — authorization-gated, read-only DNS.

dmarcaudit is PASSIVE by default: it grades SPF/DKIM/DMARC record *strings* you
supply offline. This module adds a strictly-bounded active mode that performs
**read-only DNS TXT lookups** (the exact equivalent of ``dig TXT``) so you can
audit a domain you control or are explicitly authorized to assess, without
copy-pasting records by hand.

Hard boundaries (enforced here, not just documented):
  * OFF by default. The CLI requires ``--active`` AND ``--authorized``.
  * Every queried name must match an explicit allowlist (``--allow`` /
    ``DMARCAUDIT_ALLOW``). A target not on the allowlist raises.
  * Read-only: only DNS TXT queries (QTYPE=16). No mail is sent, no SMTP
    connection is opened, no probe payload, no auth attempt — nothing that
    could alter the target. This is defensive posture assessment only.
  * Rate-limited: a token-bucket caps queries/second (default 2).

Resolution path: uses the standard library only. It first tries the OS resolver
(``socket``/``/etc/hosts``-style is not enough for TXT, so) by sending a DNS
query over UDP to a configured resolver (default 127.0.0.1 in tests, the system
resolver otherwise) and parsing the TXT answer. No third-party DNS library is
required, keeping the tool drop-in on minimal/edge hosts.
"""
from __future__ import annotations

import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional


class AuthorizationError(PermissionError):
    """Raised when active mode is used without proper authorization/allowlist."""


class NotAllowed(AuthorizationError):
    """Raised when a target is not on the explicit allowlist."""


def _norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


@dataclass
class Allowlist:
    """Explicit set of domains an operator is authorized to actively query.

    A query for ``_dmarc.example.com`` or ``sel._domainkey.example.com`` is
    allowed if ``example.com`` (or the exact name) is on the list. Wildcard-free
    and case-insensitive by design — no implicit broadening.
    """
    domains: set = field(default_factory=set)

    @classmethod
    def from_iter(cls, items) -> "Allowlist":
        return cls({_norm(i) for i in (items or []) if i and i.strip()})

    @classmethod
    def from_env(cls, env: str = "DMARCAUDIT_ALLOW") -> "Allowlist":
        raw = os.environ.get(env, "")
        return cls.from_iter(p for p in raw.replace(";", ",").split(",") if p)

    def __len__(self) -> int:
        return len(self.domains)

    def permits(self, qname: str) -> bool:
        q = _norm(qname)
        # strip well-known auth prefixes so _dmarc.X / sel._domainkey.X resolve to X
        for prefix in ("_dmarc.",):
            if q.startswith(prefix):
                q = q[len(prefix):]
        if "._domainkey." in q:
            q = q.split("._domainkey.", 1)[1]
        if q in self.domains:
            return True
        parts = q.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in self.domains:
                return True
        return False


@dataclass
class RateLimiter:
    """Simple token-bucket: at most ``rate`` queries per second (burst=rate)."""
    rate: float = 2.0
    _tokens: float = field(default=0.0, init=False)
    _last: float = field(default_factory=time.monotonic, init=False)
    _clock = staticmethod(time.monotonic)
    _sleep = staticmethod(time.sleep)

    def __post_init__(self):
        self._tokens = self.rate

    def acquire(self) -> None:
        now = self._clock()
        self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens < 1.0:
            wait = (1.0 - self._tokens) / self.rate
            self._sleep(wait)
            self._tokens = 0.0
            self._last = self._clock()
        else:
            self._tokens -= 1.0


# --------------------------------------------------------------------------- #
# Minimal stdlib DNS TXT query (read-only, QTYPE=16).
# --------------------------------------------------------------------------- #
def _encode_qname(name: str) -> bytes:
    out = b""
    for label in _norm(name).split("."):
        if label:
            b = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
            out += bytes([len(b)]) + b
    return out + b"\x00"


def build_txt_query(name: str, txid: Optional[int] = None) -> bytes:
    """Build a read-only DNS query packet for TXT (QTYPE=16, QCLASS=IN)."""
    if txid is None:
        txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    question = _encode_qname(name) + struct.pack(">HH", 16, 1)
    return header + question


def parse_txt_response(packet: bytes) -> list:
    """Parse TXT answers out of a DNS response. Returns a list of strings."""
    if len(packet) < 12:
        return []
    qd, an = struct.unpack(">HH", packet[4:8])
    off = 12
    for _ in range(qd):  # skip questions
        off = _skip_name(packet, off)
        off += 4
    answers = []
    for _ in range(an):
        off = _skip_name(packet, off)
        if off + 10 > len(packet):
            break
        atype, _aclass, _ttl, rdlen = struct.unpack(">HHIH", packet[off:off + 10])
        off += 10
        rdata = packet[off:off + rdlen]
        off += rdlen
        if atype == 16:  # TXT
            answers.append(_decode_txt_rdata(rdata))
    return answers


def _skip_name(packet: bytes, off: int) -> int:
    while off < len(packet):
        length = packet[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return off + 2
        off += 1 + length
    return off


def _decode_txt_rdata(rdata: bytes) -> str:
    parts, i = [], 0
    while i < len(rdata):
        n = rdata[i]
        parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
        i += 1 + n
    return "".join(parts)


@dataclass
class ActiveResolver:
    """Read-only DNS TXT resolver, authorization- and rate-gated.

    Parameters mirror the CLI flags. ``authorized`` must be True and the target
    must be on ``allowlist`` or :meth:`txt` raises before any packet is sent.
    """
    authorized: bool = False
    allowlist: Allowlist = field(default_factory=Allowlist)
    resolver: str = "127.0.0.1"
    port: int = 53
    timeout: float = 4.0
    limiter: RateLimiter = field(default_factory=lambda: RateLimiter(2.0))
    # injection point for tests: a callable(name)->list[str] bypassing the socket
    _transport = None

    def _check(self, qname: str) -> None:
        if not self.authorized:
            raise AuthorizationError(
                "active mode requires explicit --authorized (and you must be "
                "authorized to assess the target)")
        if not len(self.allowlist):
            raise NotAllowed("active mode requires a non-empty --allow allowlist")
        if not self.allowlist.permits(qname):
            raise NotAllowed(f"{qname!r} is not on the authorized allowlist")

    def txt(self, qname: str) -> list:
        """Return TXT records for ``qname`` (read-only). Gated + rate-limited."""
        self._check(qname)
        self.limiter.acquire()
        if self._transport is not None:  # test / custom transport
            return list(self._transport(qname))
        return self._udp_txt(qname)

    def _udp_txt(self, qname: str) -> list:
        query = build_txt_query(qname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(query, (self.resolver, self.port))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, ConnectionError, OSError):
            # No answer / NXDOMAIN / reset (e.g. a selector that doesn't exist).
            # Read-only and non-fatal: an absent record is simply "not present".
            return []
        finally:
            sock.close()
        return parse_txt_response(data)

    def fetch_records(self, domain: str, dkim_selector: str = "default") -> dict:
        """Fetch the SPF / DMARC / DKIM TXT records for ``domain`` (read-only).

        Returns a records dict shaped exactly like the offline ``--input`` JSON,
        so the result feeds straight into :func:`dmarcaudit.core.audit_domain`.
        """
        spf = _first_spf(self.txt(domain))
        dmarc = _first(self.txt(f"_dmarc.{_norm(domain)}"))
        dkim = None
        try:
            dkim = _first(self.txt(f"{dkim_selector}._domainkey.{_norm(domain)}"))
        except AuthorizationError:
            raise
        except Exception:  # noqa: BLE001 - selector may not exist
            dkim = None
        return {"domain": domain, "spf": spf, "dmarc": dmarc, "dkim": dkim}


def _first(records: list):
    return records[0] if records else None


def _first_spf(records: list):
    for r in records:
        if r and r.strip().lower().startswith("v=spf1"):
            return r
    return None
