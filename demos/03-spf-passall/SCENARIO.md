# Demo 03 — The catastrophic `+all` (anyone can send as you)

`legacy-mailer.example` has the single worst SPF misconfiguration in the wild:
the record ends in `+all`, which tells every receiver that **any host on the
Internet** is an authorized sender for the domain.

## Where the data came from
A common copy-paste accident or a misremembered "allow everything for testing"
that shipped to production. Surfaced during an M&A security review of an
acquired company's DNS.

- **SPF** ends in `+all` (pass-all).
- **DMARC** `p=none` and no reporting.
- **DKIM** absent.

## Run it
```sh
python -m dmarcaudit audit --input demos/03-spf-passall/records.json
python -m dmarcaudit audit --input demos/03-spf-passall/records.json --format sarif
```

## Expected
- `SPF_PASSALL` (**CRITICAL**), `DMARC_POLICY_NONE` (HIGH), `DKIM_MISSING`.
- **Spoofable: YES**, grade **F**, exit code **1**.

## How to act
Replace `+all` with `-all` *today*; it is the highest-leverage one-character
fix in email security.
