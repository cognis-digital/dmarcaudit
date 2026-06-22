# Demo 01 — "We have all three" but still spoofable

A mid-size company, `example-corp.com`, published SPF, DMARC and DKIM. On
paper they "have all three", yet the domain is still trivially spoofable.

## Where the data came from
A sysadmin captured the live records with `dig`:

```sh
dig +short TXT example-corp.com
dig +short TXT _dmarc.example-corp.com
dig +short TXT selector1._domainkey.example-corp.com
```
…and pasted them into `records.json`. No network is used by the tool.

- **SPF** ends in `~all` (softfail, not hardfail).
- **DMARC** is `p=none` (monitor-only) — spoofed mail still hits inboxes.
- **DKIM** is a ~1024-bit RSA key (deprecated).

## Run it
```sh
python -m dmarcaudit audit --input demos/01-basic/records.json
python -m dmarcaudit audit --input demos/01-basic/records.json --format json
python -m dmarcaudit audit --input demos/01-basic/records.json     --format html --output report.html
```

## Expected
- Grade capped at **D/F**, **Spoofable: YES** (DMARC not enforcing).
- Findings: `DMARC_POLICY_NONE` (HIGH), `SPF_SOFTFAIL` (MEDIUM),
  `DKIM_1024_KEY` (MEDIUM).
- Exit code **1** — usable as a CI / cron gate.

## How to act
Tighten DMARC to `p=quarantine` → `p=reject`, move SPF to `-all`, and rotate
DKIM to a 2048-bit key (see demo 06 for the hardened end state).
