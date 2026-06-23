"""Edge / air-gap threat-feed enrichment for dmarcaudit.

dmarcaudit's core audit is pure SPF/DKIM/DMARC string analysis. This optional
layer adds *threat context*: it cross-checks the IPs and include-domains an SPF
record authorizes against real, cached abuse/C2 blocklists (abuse.ch URLhaus,
Feodo Tracker, ThreatFox) so you can spot an SPF record that authorizes a host
which is already on a public block list.

It is built on the bundled ``dmarcaudit.datafeeds`` ingester (stdlib-only,
keyless, disk-cached, ``offline=True`` re-serve, sneakernet snapshot support).
No intel is fabricated: a blocklist entry exists only if a real feed was
fetched/cached, and the catalog lives in ``data_feeds_2026.json``.

Offline / air-gap workflow
--------------------------
    # On a connected box, refresh the abuse feeds into the local cache:
    python -m dmarcaudit.datafeeds update urlhaus feodo-c2 threatfox
    # Export the cache for sneakernet transfer to a disconnected enclave:
    python -m dmarcaudit.datafeeds snapshot-export feeds.tar.gz
    # Inside the air gap:
    python -m dmarcaudit.datafeeds snapshot-import feeds.tar.gz
    # Then audits enrich purely from cache (no network):
    dmarcaudit audit --input records.json --enrich --offline
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from . import datafeeds

# abuse.ch / blocklist feeds in the catalog that carry IPs or domains/URLs.
ABUSE_FEEDS = ("urlhaus", "feodo-c2", "threatfox")

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


class AbuseBlocklist:
    """An in-memory set of bad IPs/domains harvested from cached abuse feeds.

    Construct via :func:`load` (which reads only what is already cached when
    ``offline=True``). The object exposes ``has_ip`` / ``has_domain`` so it can
    be passed straight to :func:`dmarcaudit.core.enrich_with_feeds`.
    """

    def __init__(self, ips: Optional[Iterable[str]] = None,
                 domains: Optional[Iterable[str]] = None):
        self.ips = {i.strip() for i in (ips or []) if i.strip()}
        self.domains = {d.strip().lower().rstrip(".") for d in (domains or []) if d.strip()}

    def __len__(self) -> int:
        return len(self.ips) + len(self.domains)

    def has_ip(self, ip: str) -> bool:
        return ip.strip() in self.ips

    def has_domain(self, domain: str) -> bool:
        d = domain.strip().lower().rstrip(".")
        if d in self.domains:
            return True
        # also match a parent zone (sub.evil.example matches evil.example)
        parts = d.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in self.domains:
                return True
        return False

    def add_text(self, text: str) -> None:
        """Scrape IPs and domains out of an arbitrary feed body (CSV/plain)."""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for ip in _IP_RE.findall(line):
                self.ips.add(ip)
            for dom in _DOMAIN_RE.findall(line):
                self.domains.add(dom.lower().rstrip("."))


def load(feeds: Iterable[str] = ABUSE_FEEDS, *, offline: bool = True,
         max_age_hours: float = 24.0) -> AbuseBlocklist:
    """Build an :class:`AbuseBlocklist` from cached (or freshly fetched) feeds.

    With ``offline=True`` (the default) only the on-disk cache is read; feeds
    that were never cached are silently skipped so an air-gapped box still
    works. With ``offline=False`` missing/stale feeds are refreshed first.
    """
    bl = AbuseBlocklist()
    for feed_id in feeds:
        try:
            data = datafeeds.get(feed_id, offline=offline, max_age_hours=max_age_hours)
        except (FileNotFoundError, KeyError, ConnectionError):
            continue  # not cached / offline / network down — skip, don't fabricate
        if isinstance(data, (dict, list)):
            bl.add_text(_flatten(data))
        else:
            bl.add_text(str(data))
    return bl


def _flatten(obj) -> str:
    """Turn a parsed JSON feed into newline-joined leaf strings for scraping."""
    out: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        else:
            out.append(str(x))

    walk(obj)
    return "\n".join(out)
