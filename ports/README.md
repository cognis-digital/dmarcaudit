# Ports of dmarcaudit

The same **audit** logic — parse SPF/DKIM/DMARC TXT records and grade a domain's
email-spoofing posture — ported across languages so you can drop dmarcaudit into
any stack or ship a single static binary. Every port is **passive** (it grades
record strings you supply; no network), shares the Python reference's finding
codes (`SPF_PASSALL`, `DMARC_POLICY_NONE`, `DKIM_WEAK_KEY`, …), emits the same
JSON shape, and uses the same CI-friendly exit code (non-zero when the domain is
spoofable or has a HIGH+ finding).

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`../dmarcaudit/`](../dmarcaudit/) | `python -m dmarcaudit audit --input records.json` | `pytest` |
| JavaScript / Node | [`javascript/`](javascript/) | `node ports/javascript/index.js audit --input records.json` | `node ports/javascript/test.js` |
| Go | [`go/`](go/) | `cd ports/go && go run . audit --input ../../demos/03-spf-passall/records.json` | `go test ./...` |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- audit --domain x.com --spf "v=spf1 +all"` | `cargo test` |

All four accept the same CLI surface:

```
audit --input <records.json>
audit --domain <d> --spf "..." --dmarc "..." --dkim "..."
```

and the Python/JS ports also read a records JSON object from stdin via the `-`
argument. Output is the graded `AuditResult` as JSON (Python/JS/Go) or a compact
JSON summary (Rust).

## Verification

The Node port is exercised by `ports/javascript/test.js`; the Go and Rust ports
ship `*_test.go` / `#[cfg(test)]` suites. All three are built and tested on every
push by the [`ports` CI workflow](../.github/workflows/ports.yml) — so the ports
are real and continuously verified, not vaporware, even if a given toolchain is
not installed on your machine.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).
