# Demo 07 — A parked / non-sending domain locked down correctly

`we-dont-send.example` never sends email (a brand-protection or parked
domain). The correct posture is a "null" configuration that rejects everything,
which stops attackers from spoofing a domain you don't even use.

## Where the data came from
Brand-protection registrations and legacy domains that exist only to be owned.
Best practice (M3AAWG) is an empty-sender SPF plus an enforcing DMARC.

- **SPF** `v=spf1 -all` (no authorized senders at all).
- **DMARC** `p=reject; sp=reject`.
- **DKIM** intentionally absent (nothing signs mail).

## Run it
```sh
python -m dmarcaudit audit --input demos/07-parked-domain/records.json
```

## Expected
- **Spoofable: no** — DMARC enforces and SPF authorizes nobody.
- A `DKIM_MISSING` (MEDIUM) note, which is acceptable-by-design for a
  non-sending domain; SPF/DMARC are what matter here.

## How to act
This is the recommended lock-down for any domain that does not send mail. Use
it as a template for your parked-domain inventory.
