<a name="top"></a>

<div align="center">



<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=DMARCAUDIT&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="DMARCAUDIT"/>



# DMARCAUDIT



### Grade SPF/DKIM/DMARC posture & spoofability from DNS records



<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Grade+SPFDKIMDMARC+posture++spoofability+from+DNS+records;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>



[![PyPI](https://img.shields.io/pypi/v/cognis-dmarcaudit.svg?color=6b46c1)](https://pypi.org/project/cognis-dmarcaudit/) [![CI](https://github.com/cognis-digital/dmarcaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/dmarcaudit/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)



*Part of the Cognis Neural Suite.*



</div>



```bash

pip install cognis-dmarcaudit

dmarcaudit audit --input records.json    # → graded posture + prioritized findings

```



## Usage — step by step

1. **Install** the CLI:
   ```bash
   pip install dmarcaudit
   ```

2. **Audit a domain's email-auth records** — pass SPF/DKIM/DMARC inline, or `--input` a JSON file:
   ```bash
   dmarcaudit audit --domain example.com --spf "v=spf1 -all" --dmarc "v=DMARC1; p=reject"
   ```

3. **Score posture from a records file** exported elsewhere:
   ```bash
   dmarcaudit audit --input records.json
   ```

4. **Read the output.** Choose `table`, `json`, or `html`, and persist it with `--output`:
   ```bash
   dmarcaudit audit --domain example.com --format html --output dmarc.html
   ```

5. **Wire it into CI** to catch spoofability regressions:
   ```bash
   dmarcaudit audit --input records.json --format json || exit 1
   ```

## Contents



- [Why dmarcaudit?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)



<a name="why"></a>

## Why dmarcaudit?



Grade SPF/DKIM/DMARC posture & spoofability from DNS records — without standing up heavyweight infrastructure.



`dmarcaudit` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="features"></a>

## Features



- ✅ Parse SPF, DMARC and DKIM TXT records (offline — feed it a `dig` dump)

- ✅ Grade spoofability 0–100 with a letter grade and prioritized findings

- ✅ Catches the real failure modes: `+all` pass-all, `p=none`, softfail,
  `>10` SPF lookups (RFC 7208), partial `pct`, `sp=none`, weak DKIM keys

- ✅ Output as **table · JSON · HTML · SARIF 2.1.0** (`--format sarif` for
  GitHub code-scanning / SIEM ingest)

- ✅ Non-zero exit on HIGH+ or spoofable → drop-in CI / cron gate

- ✅ Eight runnable [demos](demos/) covering distinct real-world scenarios

- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer

- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="quick-start"></a>

## Quick start



```bash

pip install cognis-dmarcaudit

dmarcaudit --version

# Audit inline records (no file needed):
dmarcaudit audit --domain example.com \
  --spf "v=spf1 include:_spf.google.com -all" \
  --dmarc "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"

# Audit a captured dig dump:
dmarcaudit audit --input records.json                  # graded table
dmarcaudit audit --input records.json --format json    # machine-readable
dmarcaudit audit --input records.json --format sarif    # code-scanning / SIEM
dmarcaudit audit --input records.json || echo "posture needs work"  # CI gate

```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="example"></a>

## Example



```text

$ dmarcaudit audit --input demos/03-spf-passall/records.json
================================================================
 DMARCAUDIT  legacy-mailer.example
================================================================
 Grade      : F   (score 35/100)
 Spoofable  : YES — at risk
 SPF        : present  all=+all
 DMARC      : present  p=none
 DKIM       : MISSING
----------------------------------------------------------------
 Findings (4):
  [CRITICAL] SPF/SPF_PASSALL
      SPF ends in +all — ANY host on the Internet passes SPF ...
      -> Replace +all with -all immediately.
  [HIGH    ] DMARC/DMARC_POLICY_NONE
      DMARC policy is p=none (monitor only) ...
  ...
================================================================
```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="demos"></a>

## Demos

Eight self-contained, runnable scenarios live in [`demos/`](demos/). Each folder
has a `records.json` (the tool's real input format — a captured `dig` dump) and
a `SCENARIO.md` explaining where the data came from, the exact command, what to
expect, and how to remediate. Every demo is verified by the test suite to fire
the findings it documents. The DKIM keys are **real** RSA public keys
(2048/1024/512-bit) generated locally — no fabricated key material.

| Demo | Scenario | Headline finding |
|---|---|---|
| [`01-basic`](demos/01-basic/) | "We have all three" but still spoofable | `DMARC_POLICY_NONE` (HIGH) |
| [`02-hardened-pass`](demos/02-hardened-pass/) | Correctly hardened gold-standard domain | none — grade A, exit 0 |
| [`03-spf-passall`](demos/03-spf-passall/) | Catastrophic `+all` (anyone can send as you) | `SPF_PASSALL` (CRITICAL) |
| [`04-spf-too-many-lookups`](demos/04-spf-too-many-lookups/) | SPF over the 10-lookup limit → PermError | `SPF_TOO_MANY_LOOKUPS` (HIGH) |
| [`05-dkim-weak-key`](demos/05-dkim-weak-key/) | Forgeable 512-bit DKIM key | `DKIM_WEAK_KEY` (CRITICAL) |
| [`06-partial-rollout`](demos/06-partial-rollout/) | DMARC deployment caught mid-flight | `DMARC_PARTIAL_PCT` + `sp=none` |
| [`07-parked-domain`](demos/07-parked-domain/) | Non-sending domain locked down correctly | spoofable: no |
| [`08-subdomain-takeover-vector`](demos/08-subdomain-takeover-vector/) | Strong policy undermined by `sp=none` | `DMARC_SUBDOMAIN_NONE` |

```sh
# Run any demo:
python -m dmarcaudit audit --input demos/03-spf-passall/records.json
# Export SARIF for code-scanning:
python -m dmarcaudit audit --input demos/03-spf-passall/records.json \
    --format sarif --output dmarc.sarif
```

(Regenerate the corpus with `python scripts/gen_demos.py`.)

<div align="right"><a href="#top">↑ back to top</a></div>



<a name="architecture"></a>

## Architecture



```mermaid
flowchart LR
  IN[target / manifest] --> P[dmarcaudit<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="ai-stack"></a>

## Use it from any AI stack



`dmarcaudit` is interoperable with every popular way of using AI:



- **MCP server** — `dmarcaudit mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))

- **OpenAI-compatible / JSON** — pipe `dmarcaudit scan . --format json` into any agent or LLM

- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line

- **CI / scripts** — exit codes + SARIF for non-AI pipelines



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="how-it-compares"></a>

## How it compares



| | **Cognis dmarcaudit** | typical tools |

|---|:---:|:---:|

| Self-hostable, no account | ✅ | varies |

| Single command, zero config | ✅ | ⚠️ |

| JSON + SARIF for CI | ✅ | varies |

| MCP-native (AI agents) | ✅ | ❌ |

| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |

| Open license | ✅ COCL | varies |

<div align="right"><a href="#top">↑ back to top</a></div>



<a name="integrations"></a>

## Integrations



Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`dmarcaudit mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="install-anywhere"></a>

## Install — every way, every platform



```bash

pip install "git+https://github.com/cognis-digital/dmarcaudit.git"    # pip (works today)

pipx install "git+https://github.com/cognis-digital/dmarcaudit.git"   # isolated CLI

uv tool install "git+https://github.com/cognis-digital/dmarcaudit.git" # uv

pip install cognis-dmarcaudit                                          # PyPI (when published)

docker run --rm ghcr.io/cognis-digital/dmarcaudit:latest --help        # Docker

brew install cognis-digital/tap/dmarcaudit                             # Homebrew tap

curl -fsSL https://raw.githubusercontent.com/cognis-digital/dmarcaudit/main/install.sh | sh

```



| Linux | macOS | Windows | Docker | Cloud |

|---|---|---|---|---|

| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/dmarcaudit` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="related"></a>

## Related Cognis tools





**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="contributing"></a>

## Contributing



PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).



> ### ⭐ If `dmarcaudit` saved you time, **star it** — it genuinely helps others find it.



## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License



Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).



---



<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

