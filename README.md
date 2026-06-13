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

dmarcaudit scan .            # → prioritized findings in seconds

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



- [Why dmarcaudit?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)



<a name="why"></a>

## Why dmarcaudit?



Grade SPF/DKIM/DMARC posture & spoofability from DNS records — without standing up heavyweight infrastructure.



`dmarcaudit` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="features"></a>

## Features



- ✅ Parse Spf

- ✅ Parse Dmarc

- ✅ Parse Dkim

- ✅ Grade

- ✅ Audit Domain

- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer

- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="quick-start"></a>

## Quick start



```bash

pip install cognis-dmarcaudit

dmarcaudit --version

dmarcaudit scan .                       # scan current project

dmarcaudit scan . --format json         # machine-readable

dmarcaudit scan . --fail-on high        # CI gate (non-zero exit)

```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="example"></a>

## Example



```text

$ dmarcaudit scan .

  [HIGH    ] DMA-001  example finding             (./src/app.py)

  [MEDIUM  ] DMA-002  another signal              (./config.yaml)



  2 findings · risk score 5 · 38ms

```



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



## License



Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).



---



<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

