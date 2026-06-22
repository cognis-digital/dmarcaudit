#!/usr/bin/env python3
"""Generate the demos/ corpus for dmarcaudit.

Each demo is a folder demos/<NN-name>/ holding a records.json in the tool's
real input format plus a SCENARIO.md narrative. Run from the repo root:

    python scripts/gen_demos.py

All DKIM keys below are REAL RSA public keys (2048/1024/512-bit) generated
locally for these fixtures — no fabricated key material. No live domain's
private records are included; domains are illustrative (RFC 2606 / example.*
style) and the records reflect documented, real-world misconfiguration shapes.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEMOS = os.path.join(ROOT, "demos")

# Real RSA public keys (DER SubjectPublicKeyInfo, base64) generated locally.
DKIM_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6f2qBNj811HK+iXkcVZ"
    "2RaaoAcgj8TPTokcPdMJnQPvjLpJtUc441mqtQCZNjc8F1x/G7nyRA4r+AnC/crj"
    "kLAEdJDUHROAZqc1UJJLr5FN8XwWIx4O+Zk0yw1rWgPsCwB/PwZDtLgL8YAVlRX+"
    "6ygxWjJlvy7QIka7HTcQL33Hh1XddasFdGOnixgLqRGFgImVGIRW09VerwV2xVLN"
    "7gELNDGowZWBh5OdkUeLqi/c4eG2b+AiwcmuGR3G4u8sbyXY1oHNqo7lSicUx4cY"
    "SJWZJOXJ5xDfaFv8bdd0wxyQmEyNsHsieaYpC/dhK5t/hoHB2GTqrF8fZBBuBG5S"
    "/QIDAQAB"
)
DKIM_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnd2CofUYPoqEU1TTeiD9wJFu4"
    "qRAvnF+DEzSVXy2JxGEvJtlmnFdKapuVYzdZN7nJcXcNp5W/PaNMRYZdxNBd4w5w"
    "QdhWo6usbN7OpfGWL14hbr5SlPxhOlu9k9irq4MDm4CbS6k5Bv9p/5vv35ZTtq39"
    "ZuM0t8DyXCsqc1qmvQIDAQAB"
)
DKIM_512 = (
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKW8aKnGpflynUWfpqSOUNbWjE3GEFsT"
    "IQ4CqidjPXJ+lsJilkHfRSIOk3pQ5R8azrfXZeDvahxoZSEDIqqK+NUCAwEAAQ=="
)


def dkim(p, **extra):
    tags = {"v": "DKIM1", "k": "rsa", "p": p}
    tags.update(extra)
    return "; ".join(f"{k}={v}" for k, v in tags.items())


DEMOS_SPEC = [
    # (folder, records dict, scenario markdown)
    (
        "01-basic",
        {
            "domain": "example-corp.com",
            "spf": "v=spf1 include:_spf.google.com include:sendgrid.net ~all",
            "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@example-corp.com; pct=100",
            "dkim": dkim(DKIM_1024),
        },
        """# Demo 01 — "We have all three" but still spoofable

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
python -m dmarcaudit audit --input demos/01-basic/records.json \
    --format html --output report.html
```

## Expected
- Grade capped at **D/F**, **Spoofable: YES** (DMARC not enforcing).
- Findings: `DMARC_POLICY_NONE` (HIGH), `SPF_SOFTFAIL` (MEDIUM),
  `DKIM_1024_KEY` (MEDIUM).
- Exit code **1** — usable as a CI / cron gate.

## How to act
Tighten DMARC to `p=quarantine` → `p=reject`, move SPF to `-all`, and rotate
DKIM to a 2048-bit key (see demo 06 for the hardened end state).
""",
    ),
    (
        "02-hardened-pass",
        {
            "domain": "secure-bank.example",
            "spf": "v=spf1 include:_spf.google.com -all",
            "dmarc": ("v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; "
                      "rua=mailto:dmarc-rua@secure-bank.example; "
                      "ruf=mailto:dmarc-ruf@secure-bank.example"),
            "dkim": dkim(DKIM_2048),
        },
        """# Demo 02 — A correctly hardened domain (the gold standard)

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
""",
    ),
    (
        "03-spf-passall",
        {
            "domain": "legacy-mailer.example",
            "spf": "v=spf1 a mx +all",
            "dmarc": "v=DMARC1; p=none",
            "dkim": "",
        },
        """# Demo 03 — The catastrophic `+all` (anyone can send as you)

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
""",
    ),
    (
        "04-spf-too-many-lookups",
        {
            "domain": "saas-sprawl.example",
            "spf": ("v=spf1 include:_spf.google.com include:servers.mcsv.net "
                    "include:sendgrid.net include:_spf.salesforce.com "
                    "include:mail.zendesk.com include:spf.protection.outlook.com "
                    "include:_spf.intercom.io include:helpscoutemail.com "
                    "include:amazonses.com include:_spf.hubspot.com "
                    "include:stspg-customer.com -all"),
            "dmarc": "v=DMARC1; p=quarantine; rua=mailto:dmarc@saas-sprawl.example",
            "dkim": dkim(DKIM_2048),
        },
        """# Demo 04 — SPF exceeds the 10 DNS-lookup limit (PermError)

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
python -m dmarcaudit audit --input demos/04-spf-too-many-lookups/records.json \
    --format json
```

## Expected
- `SPF_TOO_MANY_LOOKUPS` (**HIGH**) reporting the lookup count.
- Exit code **1**.

## How to act
Flatten/consolidate includes (SPF flattening, or drop unused vendors) to stay
at or under 10 lookups so SPF evaluates instead of erroring out.
""",
    ),
    (
        "05-dkim-weak-key",
        {
            "domain": "old-appliance.example",
            "spf": "v=spf1 ip4:198.51.100.25 -all",
            "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@old-appliance.example",
            "dkim": dkim(DKIM_512),
        },
        """# Demo 05 — A forgeable 512-bit DKIM key

`old-appliance.example` signs mail with a DKIM key small enough to be factored
by a motivated attacker, who could then forge valid signatures. The SPF/DMARC
posture is otherwise strong, which makes the weak key the standout risk.

## Where the data came from
An ancient on-prem mail appliance generated a **512-bit** RSA DKIM key years
ago and it was never rotated. The key in `records.json` is a real 512-bit RSA
public key generated locally for this fixture.

- **SPF** `-all`, single `ip4` sender.
- **DMARC** `p=reject`.
- **DKIM** real 512-bit RSA key.

## Run it
```sh
python -m dmarcaudit audit --input demos/05-dkim-weak-key/records.json
```

## Expected
- `DKIM_WEAK_KEY` (**CRITICAL**) — key estimated well below 1024-bit.
- Exit code **1** even though SPF/DMARC look good.

## How to act
Rotate to a 2048-bit RSA DKIM key immediately and retire the appliance's old
selector.
""",
    ),
    (
        "06-partial-rollout",
        {
            "domain": "rollout-phase2.example",
            "spf": "v=spf1 include:_spf.google.com ~all",
            "dmarc": ("v=DMARC1; p=quarantine; pct=25; sp=none; "
                      "rua=mailto:dmarc@rollout-phase2.example"),
            "dkim": dkim(DKIM_2048),
        },
        """# Demo 06 — A DMARC rollout caught mid-flight

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
""",
    ),
    (
        "07-parked-domain",
        {
            "domain": "we-dont-send.example",
            "spf": "v=spf1 -all",
            "dmarc": ("v=DMARC1; p=reject; sp=reject; "
                      "rua=mailto:dmarc@we-dont-send.example"),
            "dkim": "",
        },
        """# Demo 07 — A parked / non-sending domain locked down correctly

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
""",
    ),
    (
        "08-subdomain-takeover-vector",
        {
            "domain": "marketing.bigco.example",
            "spf": "v=spf1 include:_spf.google.com -all",
            "dmarc": "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@bigco.example",
            "dkim": dkim(DKIM_2048),
        },
        """# Demo 08 — Strong org policy undermined by `sp=none`

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
python -m dmarcaudit audit \
    --input demos/08-subdomain-takeover-vector/records.json --format sarif \
    --output dmarc.sarif
```

## Expected
- `DMARC_SUBDOMAIN_NONE` (**MEDIUM**) flagged despite an otherwise strong
  posture. (No HIGH/CRITICAL, so the exit code is 0 — this is the kind of
  finding a `--format sarif` upload surfaces in code-scanning before it
  becomes an incident.)

## How to act
Remove `sp=none` (subdomains then inherit `p=reject`) or set `sp=reject`
explicitly, after confirming no legitimate subdomain depends on lax policy.
""",
    ),
]


def main():
    for folder, records, scenario in DEMOS_SPEC:
        d = os.path.join(DEMOS, folder)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "records.json"), "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)
            fh.write("\n")
        with open(os.path.join(d, "SCENARIO.md"), "w", encoding="utf-8") as fh:
            fh.write(scenario)
        print("wrote", folder)


if __name__ == "__main__":
    main()
