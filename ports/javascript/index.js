#!/usr/bin/env node
// JavaScript / Node port of the dmarcaudit core: parse SPF/DKIM/DMARC TXT
// records and grade a domain's email-spoofing posture. Zero dependencies,
// passive by default (grades record strings you supply — no network).
//
// Usage:
//   node index.js audit --input records.json
//   node index.js audit --domain x.com --spf "v=spf1 -all" --dmarc "v=DMARC1; p=reject"
//   echo '{"domain":"x","spf":"v=spf1 +all"}' | node index.js audit -
import { readFileSync } from "fs";

export const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export function parseSpf(record) {
  const out = { present: false, raw: record, all: null, mechanisms: [], lookups: 0, redirect: null, valid: false };
  if (!record) return out;
  record = String(record).trim().replace(/^"|"$/g, "");
  if (!record.toLowerCase().startsWith("v=spf1")) return out;
  out.present = true;
  out.valid = true;
  const toks = record.split(/\s+/).slice(1);
  for (const tok of toks) {
    const low = tok.toLowerCase();
    if (["+all", "-all", "~all", "?all", "all"].includes(low)) { out.all = low === "all" ? "+all" : low; continue; }
    if (low.startsWith("redirect=")) { out.redirect = tok.split("=", 2)[1]; out.lookups++; continue; }
    out.mechanisms.push(tok);
    if (low.startsWith("include:") || low.startsWith("exists:") ||
        ["a", "mx", "ptr"].includes(low) ||
        /^(a:|mx:|a\/|mx\/)/.test(low)) out.lookups++;
  }
  return out;
}

function parseTagged(record, version) {
  const tags = {};
  if (!record) return { tags, present: false };
  record = String(record).trim().replace(/^"|"$/g, "");
  if (!record.toLowerCase().startsWith(version)) return { tags, present: false };
  for (let part of record.split(";")) {
    part = part.trim();
    if (!part.includes("=")) continue;
    const i = part.indexOf("=");
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return { tags, present: true };
}

export function parseDmarc(record) {
  const { tags, present } = parseTagged(record, "v=dmarc1");
  return { present, raw: record, tags, valid: present };
}

export function parseDkim(record) {
  const out = { present: false, raw: record, tags: {}, valid: false, key_bits: null };
  if (!record) return out;
  const r = String(record).trim().replace(/^"|"$/g, "");
  const low = r.toLowerCase();
  if (!low.includes("p=") && !low.includes("v=dkim1")) return out;
  out.present = true;
  for (let part of r.split(";")) {
    part = part.trim();
    if (!part.includes("=")) continue;
    const i = part.indexOf("=");
    out.tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  const pub = out.tags.p || "";
  out.valid = Boolean(pub);
  if (pub) {
    const derLen = Math.floor((pub.replace(/\s+/g, "").length * 3) / 4);
    out.key_bits = derLen >= 380 ? 4096 : derLen >= 250 ? 2048 : derLen >= 120 ? 1024 : 512;
  }
  return out;
}

const F = (severity, record, code, message, recommendation = "") => ({ severity, record, code, message, recommendation });

function gradeSpf(spf, findings) {
  if (!spf.present) { findings.push(F("HIGH", "SPF", "SPF_MISSING", "No SPF record found.", "Publish v=spf1 include:<provider> -all")); return 0; }
  let pts = 20;
  switch (spf.all) {
    case "-all": pts += 20; break;
    case "~all": pts += 12; findings.push(F("MEDIUM", "SPF", "SPF_SOFTFAIL", "SPF ends in ~all (softfail).", "Move to -all once senders are confirmed.")); break;
    case "+all": case "all": findings.push(F("CRITICAL", "SPF", "SPF_PASSALL", "SPF ends in +all — any host passes SPF. Trivially spoofable.", "Replace +all with -all immediately.")); break;
    case "?all": pts += 4; findings.push(F("HIGH", "SPF", "SPF_NEUTRAL", "SPF ends in ?all (neutral).", "Use -all.")); break;
    default: findings.push(F("MEDIUM", "SPF", "SPF_NO_ALL", "SPF has no 'all' mechanism.", "Append -all."));
  }
  if (spf.lookups > 10) { findings.push(F("HIGH", "SPF", "SPF_TOO_MANY_LOOKUPS", `SPF requires ${spf.lookups} DNS lookups (limit 10).`, "Flatten includes to <=10 lookups.")); pts -= 10; }
  return Math.max(pts, 0);
}

function gradeDmarc(dmarc, findings) {
  if (!dmarc.present) { findings.push(F("CRITICAL", "DMARC", "DMARC_MISSING", "No DMARC record at _dmarc.<domain>.", "Publish v=DMARC1; p=quarantine; rua=mailto:...")); return 0; }
  let pts = 15;
  const t = dmarc.tags;
  const policy = (t.p || "none").toLowerCase();
  if (policy === "reject") pts += 25;
  else if (policy === "quarantine") { pts += 15; findings.push(F("LOW", "DMARC", "DMARC_QUARANTINE", "DMARC policy is p=quarantine.", "Move to p=reject when reports are clean.")); }
  else findings.push(F("HIGH", "DMARC", "DMARC_POLICY_NONE", "DMARC policy is p=none (monitor only).", "Tighten to p=quarantine then p=reject."));
  if (t.pct !== undefined && /^\d+$/.test(t.pct) && parseInt(t.pct, 10) < 100) { findings.push(F("MEDIUM", "DMARC", "DMARC_PARTIAL_PCT", `DMARC pct=${t.pct} — applies to only ${t.pct}% of mail.`, "Set pct=100.")); pts -= 5; }
  if (t.sp && t.sp.toLowerCase() === "none" && policy !== "none") { findings.push(F("MEDIUM", "DMARC", "DMARC_SUBDOMAIN_NONE", "Subdomain policy sp=none weakens protection.", "Remove sp=none or set sp=reject.")); pts -= 5; }
  if (!t.rua) findings.push(F("LOW", "DMARC", "DMARC_NO_RUA", "No aggregate report address (rua).", "Add rua=mailto:dmarc-reports@<domain>."));
  if ((t.aspf || "r").toLowerCase() === "s" || (t.adkim || "r").toLowerCase() === "s") pts += 3;
  return Math.max(pts, 0);
}

function gradeDkim(dkim, findings) {
  if (!dkim.present) { findings.push(F("MEDIUM", "DKIM", "DKIM_MISSING", "No DKIM record for the supplied selector.", "Enable DKIM signing and publish the public key.")); return 0; }
  let pts = 15;
  const bits = dkim.key_bits;
  if (bits != null) {
    if (bits < 1024) findings.push(F("CRITICAL", "DKIM", "DKIM_WEAK_KEY", `DKIM key appears to be ${bits}-bit — forgeable.`, "Rotate to a 2048-bit RSA key."));
    else if (bits < 2048) findings.push(F("MEDIUM", "DKIM", "DKIM_1024_KEY", "DKIM key is ~1024-bit (deprecated).", "Rotate to a 2048-bit RSA key."));
    else pts += 5;
  }
  if ((dkim.tags.t || "").toLowerCase().includes("y")) findings.push(F("LOW", "DKIM", "DKIM_TESTING", "DKIM record is in testing mode (t=y).", "Remove t=y once signing is verified."));
  return pts;
}

export function audit(rec) {
  const spf = parseSpf(rec.spf), dmarc = parseDmarc(rec.dmarc), dkim = parseDkim(rec.dkim);
  const findings = [];
  let score = gradeSpf(spf, findings) + gradeDmarc(dmarc, findings) + gradeDkim(dkim, findings);
  score = Math.min(score, 100);
  const policy = dmarc.present ? (dmarc.tags.p || "none").toLowerCase() : "none";
  const enforced = dmarc.present && ["quarantine", "reject"].includes(policy);
  const spoofable = !enforced || ["+all", "all"].includes(spf.all);
  if (spoofable) score = Math.min(score, 64);
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return { domain: rec.domain || "unknown", grade, score, spoofable, spf, dmarc, dkim, findings };
}

export function worstSeverity(findings) {
  let w = "INFO";
  for (const f of findings) if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[w]) w = f.severity;
  return w;
}

function loadArgs(argv) {
  const rec = { domain: null, spf: null, dmarc: null, dkim: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--input") rec.__file = argv[++i];
    else if (a === "--domain") rec.domain = argv[++i];
    else if (a === "--spf") rec.spf = argv[++i];
    else if (a === "--dmarc") rec.dmarc = argv[++i];
    else if (a === "--dkim") rec.dkim = argv[++i];
    else if (a === "-") rec.__stdin = true;
  }
  return rec;
}

function main(argv) {
  if (argv[0] !== "audit") { console.error("usage: dmarcaudit-js audit [--input f.json | --domain d --spf .. ] [-]"); return 2; }
  let rec = loadArgs(argv.slice(1));
  if (rec.__file) Object.assign(rec, JSON.parse(readFileSync(rec.__file, "utf8")));
  if (rec.__stdin) Object.assign(rec, JSON.parse(readFileSync(0, "utf8")));
  const res = audit(rec);
  console.log(JSON.stringify(res, null, 2));
  return (res.spoofable || SEVERITY_ORDER[worstSeverity(res.findings)] >= SEVERITY_ORDER.HIGH) ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main(process.argv.slice(2)));
}
