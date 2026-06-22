# Demo 08 — Strong org policy undermined by `sp=none`

`marketing.bigco.example` looks airtight: hardfail SPF, `p=reject`, 2048-bit
DKIM. But `sp=none` tells receivers to apply **no policy to subdomains** —
leaving `anything.marketing.bigco.example` open to spoofing, a favourite
phishing vector against large orgs.

## Where the data came from
A common pattern where the parent policy was hardened but `sp=none` was left in
to "avoid breaking" an unknown subdomain. Found while auditing a subsidiary's
DNS during a phishing-campaign post-mortem.

- **SPF** `-all`.
- **DMARC** `p=reject` but `sp=none`.
- **DKIM** 2048-bit.

## Run it
```sh
python -m dmarcaudit audit --input demos/08-subdomain-takeover-vector/records.json
python -m dmarcaudit audit     --input demos/08-subdomain-takeover-vector/records.json --format sarif     --output dmarc.sarif
```

## Expected
- `DMARC_SUBDOMAIN_NONE` (**MEDIUM**) flagged despite an otherwise strong
  posture. (No HIGH/CRITICAL, so the exit code is 0 — this is the kind of
  finding a `--format sarif` upload surfaces in code-scanning before it
  becomes an incident.)

## How to act
Remove `sp=none` (subdomains then inherit `p=reject`) or set `sp=reject`
explicitly, after confirming no legitimate subdomain depends on lax policy.
