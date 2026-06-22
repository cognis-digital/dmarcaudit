# Demo 04 — SPF exceeds the 10 DNS-lookup limit (PermError)

`saas-sprawl.example` keeps adding SaaS vendors to SPF. It now requires more
than the **10 DNS lookups** allowed by RFC 7208 §4.6.4, so receivers return
`permerror` and may ignore SPF entirely — silently breaking the protection the
team thinks they have.

## Where the data came from
Eleven `include:` mechanisms accreted over years as Marketing, Support and
Sales each onboarded another email vendor. Captured from production DNS.

- **SPF** has 11 `include:` lookups (> 10) and ends in `-all`.
- **DMARC** `p=quarantine`.
- **DKIM** 2048-bit.

## Run it
```sh
python -m dmarcaudit audit --input demos/04-spf-too-many-lookups/records.json
python -m dmarcaudit audit --input demos/04-spf-too-many-lookups/records.json     --format json
```

## Expected
- `SPF_TOO_MANY_LOOKUPS` (**HIGH**) reporting the lookup count.
- Exit code **1**.

## How to act
Flatten/consolidate includes (SPF flattening, or drop unused vendors) to stay
at or under 10 lookups so SPF evaluates instead of erroring out.
