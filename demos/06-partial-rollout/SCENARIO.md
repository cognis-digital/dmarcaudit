# Demo 06 — A DMARC rollout caught mid-flight

`rollout-phase2.example` is partway through a DMARC deployment: the policy is
`p=quarantine` but only applied to **25% of mail** (`pct=25`), the subdomain
policy is disabled (`sp=none`), and SPF is still on softfail.

## Where the data came from
This is the realistic intermediate state operators sit in for weeks during a
careful rollout. The audit's job is to show exactly what still needs tightening
before declaring victory.

- **SPF** `~all` (softfail).
- **DMARC** `p=quarantine`, `pct=25`, `sp=none`.
- **DKIM** 2048-bit (good).

## Run it
```sh
python -m dmarcaudit audit --input demos/06-partial-rollout/records.json
```

## Expected
- `DMARC_PARTIAL_PCT` (MEDIUM, `pct=25`), `DMARC_SUBDOMAIN_NONE` (MEDIUM),
  `SPF_SOFTFAIL` (MEDIUM), plus a `DMARC_QUARANTINE` note.
- The enforcing `p=quarantine` keeps `spoofable: no` and the exit code at
  **0** — but the three MEDIUM findings are exactly the punch-list still
  blocking a clean `p=reject` rollout.

## How to act
Ramp `pct` to 100, remove `sp=none` (or set `sp=reject`), and move SPF to
`-all`, then advance the policy to `p=reject`.
