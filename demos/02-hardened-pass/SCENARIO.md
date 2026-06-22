# Demo 02 — A correctly hardened domain (the gold standard)

`secure-bank.example` did the work: hardfail SPF, enforcing DMARC with strict
alignment and a subdomain policy, aggregate + forensic reporting, and a
2048-bit DKIM key.

## Where the data came from
The records below are what a well-run financial-services domain looks like
after a full DMARC rollout reaching `p=reject`.

- **SPF** ends in `-all` (hardfail).
- **DMARC** `p=reject`, `sp=reject`, strict alignment (`adkim=s`, `aspf=s`),
  `pct=100`, with `rua` + `ruf` reporting.
- **DKIM** is a real 2048-bit RSA key.

## Run it
```sh
python -m dmarcaudit audit --input demos/02-hardened-pass/records.json
```

## Expected
- **Spoofable: no**, grade **A/B/C**, score **>= 70**.
- No HIGH/CRITICAL findings → exit code **0**.

## How to act
This is the target state. Use it as the "known-good" fixture your CI compares
against, and keep monitoring `rua` reports for new sending sources.
