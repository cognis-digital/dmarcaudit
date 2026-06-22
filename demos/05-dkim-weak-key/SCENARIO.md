# Demo 05 — A forgeable 512-bit DKIM key

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
