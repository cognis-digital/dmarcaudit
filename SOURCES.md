# Sources

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

### Maritime
- **feed** · https://gcaptain.com/feed/
- **feed** · https://www.maritime-executive.com/rss
- **feed** · https://splash247.com/feed/
- **feed** · https://www.tradewindsnews.com/rss
- **feed** · https://lloydslist.com/rss
- **live search** · `shadow fleet sanctioned tanker AIS`
- **live search** · `ship-to-ship transfer sanctions evasion`
- **live search** · `dark vessel AIS spoofing`
- **live search** · `OFAC sanctioned vessel designation`
- **live search** · `port disruption maritime security`
- **api** · https://aisstream.io (free real-time AIS websocket, key required)
- **api** · https://globalfishingwatch.org/our-apis/ (IUU / dark activity, free API token)
- **api** · https://www.marinetraffic.com (consumer vessel tracking)
- **api** · https://sanctionssearch.ofac.treas.gov (OFAC SDN, free)

## Bundled threat-feed catalog (edge / air-gap enrichment)

The optional `--enrich` mode and the bundled ingester (`dmarcaudit/datafeeds.py`)
draw from a real, mostly-keyless feed catalog shipped in
[`dmarcaudit/data_feeds_2026.json`](dmarcaudit/data_feeds_2026.json) — 35 feeds
across vuln, threat-intel, compliance, OSINT and cloud domains. dmarcaudit uses
the **abuse.ch** subset to flag SPF records that authorize a host already on a
public block list. All feeds are fetched over HTTPS, cached to disk, and
re-served offline (`--offline`) for air-gapped use; the cache can be
sneakernetted with `snapshot-export` / `snapshot-import`.

Used by `--enrich`:
- **threat-intel** · abuse.ch **URLhaus** (malware URLs/domains, keyless)
- **threat-intel** · abuse.ch **Feodo Tracker** (botnet C2 IPs, keyless)
- **threat-intel** · abuse.ch **ThreatFox** (IOCs, keyless)

Also catalogued (for the broader suite / future enrichment): CISA KEV, EPSS,
OSV, NVD CVE, MITRE ATT&CK STIX, NIST OSCAL 800-53, OFAC, GDELT, cloud IP
ranges. List them with:

```bash
python -m dmarcaudit.datafeeds list
python -m dmarcaudit.datafeeds list --domain threat-intel
```

No intel is fabricated: an enrichment finding fires only on a real match in a
feed you actually fetched/cached.

