# Demo 01 — Basic email-auth posture audit

A mid-size company, `example-corp.com`, has published SPF, DMARC and DKIM
records. On paper they "have all three," but the configuration still leaves the
domain spoofable. This demo shows DMARCAUDIT catching that.

## Input

`records.json` holds DNS TXT records the operator already captured (e.g. via
`dig TXT example-corp.com`, `dig TXT _dmarc.example-corp.com`, and
`dig TXT selector1._domainkey.example-corp.com`). No network is used.

- **SPF**: ends in `~all` (softfail, not hardfail) — better than nothing but
  unauthorized senders are only flagged.
- **DMARC**: `p=none` — monitor-only, so spoofed mail still reaches inboxes.
- **DKIM**: ~1024-bit RSA key (deprecated).

## Run it

```sh
# Human-readable table (default)
python -m dmarcaudit audit --input demos/01-basic/records.json

# Machine-readable JSON for pipelines
python -m dmarcaudit audit --input demos/01-basic/records.json --format json

# Shareable self-contained HTML report (the "UI")
python -m dmarcaudit audit --input demos/01-basic/records.json \
    --format html --output report.html
```

You can also pass records inline instead of a file:

```sh
python -m dmarcaudit audit --domain test.com --spf "v=spf1 +all" --format table
```

## Expected outcome

- Grade is capped at **D/F** because DMARC is not enforcing (`p=none`), so the
  domain is **spoofable**.
- Findings flag `DMARC_POLICY_NONE` (HIGH), `SPF_SOFTFAIL` (MEDIUM) and
  `DKIM_1024_KEY` (MEDIUM).
- The process exits **non-zero** (a HIGH finding / spoofable domain), so it can
  gate CI or a posture-monitoring cron.

## What "good" looks like

```sh
python -m dmarcaudit audit --domain hardened.com \
  --spf "v=spf1 include:_spf.google.com -all" \
  --dmarc "v=DMARC1; p=reject; rua=mailto:d@hardened.com; pct=100" \
  --dkim "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1Z8xQ2bF8vQ3kP9mYwRtJ0aLcVnB7eHsX4uYi2dZ5fGq1oWpTkLmN3rScDgHjFvBxUaEoIzPwQ7yMnRtVbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYzQIDAQAB"
```
This reaches a passing grade and exits 0.
