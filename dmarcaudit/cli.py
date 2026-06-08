"""Command-line interface for DMARCAUDIT.

Usage:
    python -m dmarcaudit audit --input demos/01-basic/records.json --format html
    python -m dmarcaudit audit --domain example.com --spf "v=spf1 -all" ...
    python -m dmarcaudit --version

Input can come from a JSON file (--input) or directly via flags. The JSON form
keeps the tool offline and pipeline-friendly (feed it a DNS dump you already
captured). Exit code is non-zero when findings warrant attention.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import audit_domain, AuditResult, SEVERITY_ORDER

SEV_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#0369a1",
    "INFO": "#374151",
}
GRADE_COLORS = {"A": "#15803d", "B": "#65a30d", "C": "#ca8a04",
                "D": "#ea580c", "F": "#b91c1c"}


def _load_input(args) -> dict:
    """Resolve audit inputs from --input JSON file and/or direct flags."""
    data = {"domain": None, "spf": None, "dmarc": None, "dkim": None}
    if args.input:
        with open(args.input, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        for k in data:
            if k in loaded:
                data[k] = loaded[k]
    if args.domain:
        data["domain"] = args.domain
    if args.spf is not None:
        data["spf"] = args.spf
    if args.dmarc is not None:
        data["dmarc"] = args.dmarc
    if args.dkim is not None:
        data["dkim"] = args.dkim
    if not data["domain"]:
        data["domain"] = "unknown"
    return data


def _render_table(res: AuditResult) -> str:
    lines = []
    lines.append("=" * 64)
    lines.append(f" DMARCAUDIT  {res.domain}")
    lines.append("=" * 64)
    lines.append(f" Grade      : {res.grade}   (score {res.score}/100)")
    lines.append(f" Spoofable  : {'YES — at risk' if res.spoofable else 'no'}")
    lines.append(f" SPF        : {'present' if res.spf.get('present') else 'MISSING'}"
                 + (f"  all={res.spf.get('all')}" if res.spf.get('present') else ""))
    lines.append(f" DMARC      : {'present' if res.dmarc.get('present') else 'MISSING'}"
                 + (f"  p={res.dmarc.get('tags', {}).get('p', 'none')}"
                    if res.dmarc.get('present') else ""))
    lines.append(f" DKIM       : {'present' if res.dkim.get('present') else 'MISSING'}"
                 + (f"  ~{res.dkim.get('key_bits')}-bit"
                    if res.dkim.get('present') and res.dkim.get('key_bits') else ""))
    lines.append("-" * 64)
    if not res.findings:
        lines.append(" No findings. Posture looks strong.")
    else:
        lines.append(f" Findings ({len(res.findings)}):")
        for f in res.findings:
            lines.append(f"  [{f.severity:<8}] {f.record}/{f.code}")
            lines.append(f"      {f.message}")
            if f.recommendation:
                lines.append(f"      -> {f.recommendation}")
    lines.append("=" * 64)
    return "\n".join(lines)


def _render_html(res: AuditResult) -> str:
    e = html.escape
    gc = GRADE_COLORS.get(res.grade, "#374151")
    rows = []
    for f in res.findings:
        c = SEV_COLORS.get(f.severity, "#374151")
        rows.append(
            f"<tr>"
            f"<td><span class='sev' style='background:{c}'>{e(f.severity)}</span></td>"
            f"<td class='mono'>{e(f.record)}/{e(f.code)}</td>"
            f"<td>{e(f.message)}"
            + (f"<div class='rec'>&#8594; {e(f.recommendation)}</div>"
               if f.recommendation else "")
            + "</td></tr>")
    findings_html = "\n".join(rows) if rows else \
        "<tr><td colspan='3' class='ok'>No findings — posture looks strong.</td></tr>"

    def chip(label, present, extra=""):
        col = "#15803d" if present else "#b91c1c"
        txt = "present" if present else "MISSING"
        return (f"<div class='chip'><span class='dot' style='background:{col}'></span>"
                f"<b>{e(label)}</b> {e(txt)} <span class='mono'>{e(extra)}</span></div>")

    spf_extra = f"all={res.spf.get('all')}" if res.spf.get("present") else ""
    dmarc_extra = (f"p={res.dmarc.get('tags', {}).get('p', 'none')}"
                   if res.dmarc.get("present") else "")
    dkim_extra = (f"~{res.dkim.get('key_bits')}-bit"
                  if res.dkim.get("present") and res.dkim.get("key_bits") else "")
    spoof = ("<span style='color:#b91c1c;font-weight:700'>YES — at risk</span>"
             if res.spoofable else "<span style='color:#15803d'>no</span>")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DMARCAUDIT — {e(res.domain)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #0f172a; color: #e2e8f0; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 28px 20px 60px; }}
  header {{ display: flex; align-items: center; gap: 22px; flex-wrap: wrap; }}
  .grade {{ width: 96px; height: 96px; border-radius: 16px; display: flex;
            align-items: center; justify-content: center; font-size: 52px;
            font-weight: 800; color: #fff; background: {gc}; flex: 0 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color: #94a3b8; font-size: 14px; }}
  .score {{ font-size: 15px; margin-top: 6px; }}
  .chips {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 22px 0; }}
  .chip {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px;
          padding: 10px 14px; font-size: 13px; }}
  .dot {{ display: inline-block; width: 9px; height: 9px; border-radius: 50%;
         margin-right: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px;
          background: #1e293b; border-radius: 10px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 11px 14px; vertical-align: top;
           border-bottom: 1px solid #334155; font-size: 14px; }}
  th {{ background: #0b1220; color: #94a3b8; text-transform: uppercase;
       font-size: 11px; letter-spacing: .06em; }}
  .sev {{ color: #fff; padding: 2px 9px; border-radius: 20px; font-size: 11px;
         font-weight: 700; white-space: nowrap; }}
  .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px;
          color: #cbd5e1; }}
  .rec {{ color: #7dd3fc; font-size: 13px; margin-top: 5px; }}
  .ok {{ color: #4ade80; text-align: center; padding: 18px; }}
  footer {{ margin-top: 26px; color: #64748b; font-size: 12px; }}
</style></head>
<body><div class="wrap">
  <header>
    <div class="grade">{e(res.grade)}</div>
    <div>
      <h1>Email Spoofing Posture — {e(res.domain)}</h1>
      <div class="sub">DMARCAUDIT v{TOOL_VERSION} · SPF / DKIM / DMARC analysis</div>
      <div class="score">Score <b>{res.score}/100</b> &nbsp;·&nbsp; Spoofable: {spoof}</div>
    </div>
  </header>
  <div class="chips">
    {chip("SPF", res.spf.get("present"), spf_extra)}
    {chip("DMARC", res.dmarc.get("present"), dmarc_extra)}
    {chip("DKIM", res.dkim.get("present"), dkim_extra)}
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Detail &amp; Fix</th></tr></thead>
    <tbody>
    {findings_html}
    </tbody>
  </table>
  <footer>Generated offline by {e(TOOL_NAME)} v{TOOL_VERSION}.
  Defensive analysis of records you control — no mail was sent or spoofed.</footer>
</div></body></html>"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Grade SPF/DKIM/DMARC posture & spoofability from DNS records.")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="Audit a domain's email-auth records.")
    a.add_argument("--input", help="JSON file with domain/spf/dmarc/dkim records.")
    a.add_argument("--domain", help="Domain name (label only).")
    a.add_argument("--spf", help="Raw SPF TXT record string.")
    a.add_argument("--dmarc", help="Raw DMARC TXT record string.")
    a.add_argument("--dkim", help="Raw DKIM public-key TXT record string.")
    a.add_argument("--format", choices=["table", "json", "html"],
                   default="table", help="Output format.")
    a.add_argument("--output", "-o", help="Write report to this file path.")
    return p


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "audit":
        parser.print_help()
        return 2

    if not args.input and not (args.domain or args.spf or args.dmarc or args.dkim):
        parser.error("provide --input or at least one of "
                     "--domain/--spf/--dmarc/--dkim")

    try:
        data = _load_input(args)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read input: {exc}", file=sys.stderr)
        return 2

    res = audit_domain(data["domain"], data.get("spf"), data.get("dmarc"),
                       data.get("dkim"))

    if args.format == "json":
        out = json.dumps(res.to_dict(), indent=2)
    elif args.format == "html":
        out = _render_html(res)
    else:
        out = _render_table(res)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
            print(f"report written to {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"error: could not write output: {exc}", file=sys.stderr)
            return 2
    else:
        print(out)

    # Exit non-zero when findings warrant attention (HIGH or worse, or spoofable).
    worst = res.worst_severity
    if res.spoofable or SEVERITY_ORDER[worst] >= SEVERITY_ORDER["HIGH"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
