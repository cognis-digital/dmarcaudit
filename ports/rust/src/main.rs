//! Rust port of the dmarcaudit core: parse SPF/DKIM/DMARC TXT records and grade
//! a domain's email-spoofing posture. Fast single binary, zero external crates,
//! passive by default (grades record strings you supply — no network).
//!
//! Usage:
//!   dmarcaudit-rs audit --domain x.com --spf "v=spf1 -all" --dmarc "v=DMARC1; p=reject"
//!   dmarcaudit-rs audit --input records.json
//!
//! Exit code is non-zero when the domain is spoofable or carries a HIGH+
//! finding, matching the Python and Go ports for drop-in CI parity.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::exit;

#[derive(Clone)]
pub struct Finding {
    pub severity: &'static str,
    pub record: &'static str,
    pub code: &'static str,
    pub message: String,
    pub recommendation: &'static str,
}

fn sev_rank(s: &str) -> i32 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

#[derive(Default)]
pub struct Records {
    pub domain: String,
    pub spf: String,
    pub dmarc: String,
    pub dkim: String,
}

pub struct Spf {
    pub present: bool,
    pub valid: bool,
    pub all: Option<String>,
    pub lookups: usize,
}

pub fn parse_spf(record: &str) -> Spf {
    let rec = record.trim().trim_matches('"');
    if rec.is_empty() || !rec.to_lowercase().starts_with("v=spf1") {
        return Spf { present: false, valid: false, all: None, lookups: 0 };
    }
    let mut all = None;
    let mut lookups = 0usize;
    for tok in rec.split_whitespace().skip(1) {
        let low = tok.to_lowercase();
        match low.as_str() {
            "+all" | "-all" | "~all" | "?all" => { all = Some(low.clone()); continue; }
            "all" => { all = Some("+all".to_string()); continue; }
            _ => {}
        }
        if low.starts_with("redirect=") { lookups += 1; continue; }
        if low.starts_with("include:") || low.starts_with("exists:")
            || low == "a" || low == "mx" || low == "ptr"
            || low.starts_with("a:") || low.starts_with("mx:")
            || low.starts_with("a/") || low.starts_with("mx/")
        {
            lookups += 1;
        }
    }
    Spf { present: true, valid: true, all, lookups }
}

fn parse_tags(record: &str, version: &str) -> (HashMap<String, String>, bool) {
    let mut tags = HashMap::new();
    let rec = record.trim().trim_matches('"');
    if rec.is_empty() || !rec.to_lowercase().starts_with(version) {
        return (tags, false);
    }
    for part in rec.split(';') {
        let part = part.trim();
        if let Some(i) = part.find('=') {
            tags.insert(part[..i].trim().to_lowercase(), part[i + 1..].trim().to_string());
        }
    }
    (tags, true)
}

pub struct Dmarc {
    pub present: bool,
    pub tags: HashMap<String, String>,
}

pub fn parse_dmarc(record: &str) -> Dmarc {
    let (tags, present) = parse_tags(record, "v=dmarc1");
    Dmarc { present, tags }
}

pub struct Dkim {
    pub present: bool,
    pub key_bits: Option<u32>,
    pub tags: HashMap<String, String>,
}

pub fn parse_dkim(record: &str) -> Dkim {
    let rec = record.trim().trim_matches('"');
    let low = rec.to_lowercase();
    if rec.is_empty() || (!low.contains("p=") && !low.contains("v=dkim1")) {
        return Dkim { present: false, key_bits: None, tags: HashMap::new() };
    }
    let mut tags = HashMap::new();
    for part in rec.split(';') {
        let part = part.trim();
        if let Some(i) = part.find('=') {
            tags.insert(part[..i].trim().to_lowercase(), part[i + 1..].trim().to_string());
        }
    }
    let key_bits = tags.get("p").filter(|p| !p.is_empty()).map(|p| {
        let clean: String = p.chars().filter(|c| !c.is_whitespace()).collect();
        let der_len = (clean.len() as f64 * 3.0 / 4.0) as usize;
        if der_len >= 380 { 4096 } else if der_len >= 250 { 2048 }
        else if der_len >= 120 { 1024 } else { 512 }
    });
    Dkim { present: true, key_bits, tags }
}

fn f(findings: &mut Vec<Finding>, sev: &'static str, rec: &'static str, code: &'static str, msg: String, fix: &'static str) {
    findings.push(Finding { severity: sev, record: rec, code, message: msg, recommendation: fix });
}

fn grade_spf(spf: &Spf, findings: &mut Vec<Finding>) -> i32 {
    if !spf.present {
        f(findings, "HIGH", "SPF", "SPF_MISSING", "No SPF record found.".into(), "Publish v=spf1 include:<provider> -all");
        return 0;
    }
    let mut pts = 20;
    match spf.all.as_deref() {
        Some("-all") => pts += 20,
        Some("~all") => { pts += 12; f(findings, "MEDIUM", "SPF", "SPF_SOFTFAIL", "SPF ends in ~all (softfail).".into(), "Move to -all once senders are confirmed."); }
        Some("+all") | Some("all") => f(findings, "CRITICAL", "SPF", "SPF_PASSALL", "SPF ends in +all — any host passes SPF. Trivially spoofable.".into(), "Replace +all with -all immediately."),
        Some("?all") => { pts += 4; f(findings, "HIGH", "SPF", "SPF_NEUTRAL", "SPF ends in ?all (neutral).".into(), "Use -all."); }
        _ => f(findings, "MEDIUM", "SPF", "SPF_NO_ALL", "SPF has no 'all' mechanism.".into(), "Append -all."),
    }
    if spf.lookups > 10 {
        f(findings, "HIGH", "SPF", "SPF_TOO_MANY_LOOKUPS", format!("SPF requires {} DNS lookups (limit 10).", spf.lookups), "Flatten includes to <=10 lookups.");
        pts -= 10;
    }
    pts.max(0)
}

fn grade_dmarc(dmarc: &Dmarc, findings: &mut Vec<Finding>) -> i32 {
    if !dmarc.present {
        f(findings, "CRITICAL", "DMARC", "DMARC_MISSING", "No DMARC record at _dmarc.<domain>.".into(), "Publish v=DMARC1; p=quarantine; rua=mailto:...");
        return 0;
    }
    let mut pts = 15;
    let policy = dmarc.tags.get("p").map(|s| s.to_lowercase()).unwrap_or_else(|| "none".into());
    match policy.as_str() {
        "reject" => pts += 25,
        "quarantine" => { pts += 15; f(findings, "LOW", "DMARC", "DMARC_QUARANTINE", "DMARC policy is p=quarantine.".into(), "Move to p=reject when reports are clean."); }
        _ => f(findings, "HIGH", "DMARC", "DMARC_POLICY_NONE", "DMARC policy is p=none (monitor only).".into(), "Tighten to p=quarantine then p=reject."),
    }
    if let Some(pct) = dmarc.tags.get("pct") {
        if let Ok(n) = pct.parse::<i32>() {
            if n < 100 {
                f(findings, "MEDIUM", "DMARC", "DMARC_PARTIAL_PCT", format!("DMARC pct={} — applies to only {}% of mail.", pct, pct), "Set pct=100.");
                pts -= 5;
            }
        }
    }
    if let Some(sp) = dmarc.tags.get("sp") {
        if sp.to_lowercase() == "none" && policy != "none" {
            f(findings, "MEDIUM", "DMARC", "DMARC_SUBDOMAIN_NONE", "Subdomain policy sp=none weakens protection.".into(), "Remove sp=none or set sp=reject.");
            pts -= 5;
        }
    }
    if dmarc.tags.get("rua").map_or(true, |s| s.is_empty()) {
        f(findings, "LOW", "DMARC", "DMARC_NO_RUA", "No aggregate report address (rua).".into(), "Add rua=mailto:dmarc-reports@<domain>.");
    }
    let s = |k: &str| dmarc.tags.get(k).map(|v| v.to_lowercase()).unwrap_or_else(|| "r".into());
    if s("aspf") == "s" || s("adkim") == "s" { pts += 3; }
    pts.max(0)
}

fn grade_dkim(dkim: &Dkim, findings: &mut Vec<Finding>) -> i32 {
    if !dkim.present {
        f(findings, "MEDIUM", "DKIM", "DKIM_MISSING", "No DKIM record for the supplied selector.".into(), "Enable DKIM signing and publish the public key.");
        return 0;
    }
    let mut pts = 15;
    if let Some(bits) = dkim.key_bits {
        if bits < 1024 {
            f(findings, "CRITICAL", "DKIM", "DKIM_WEAK_KEY", format!("DKIM key appears to be {}-bit — forgeable.", bits), "Rotate to a 2048-bit RSA key.");
        } else if bits < 2048 {
            f(findings, "MEDIUM", "DKIM", "DKIM_1024_KEY", "DKIM key is ~1024-bit (deprecated).".into(), "Rotate to a 2048-bit RSA key.");
        } else {
            pts += 5;
        }
    }
    if dkim.tags.get("t").map_or(false, |t| t.to_lowercase().contains('y')) {
        f(findings, "LOW", "DKIM", "DKIM_TESTING", "DKIM record is in testing mode (t=y).".into(), "Remove t=y once signing is verified.");
    }
    pts
}

pub struct AuditResult {
    pub domain: String,
    pub grade: char,
    pub score: i32,
    pub spoofable: bool,
    pub findings: Vec<Finding>,
}

pub fn audit(r: &Records) -> AuditResult {
    let spf = parse_spf(&r.spf);
    let dmarc = parse_dmarc(&r.dmarc);
    let dkim = parse_dkim(&r.dkim);
    let mut findings = Vec::new();
    let mut score = grade_spf(&spf, &mut findings) + grade_dmarc(&dmarc, &mut findings) + grade_dkim(&dkim, &mut findings);
    if score > 100 { score = 100; }
    let policy = if dmarc.present {
        dmarc.tags.get("p").map(|s| s.to_lowercase()).unwrap_or_else(|| "none".into())
    } else { "none".into() };
    let enforced = dmarc.present && (policy == "quarantine" || policy == "reject");
    let all = spf.all.as_deref();
    let spoofable = !enforced || all == Some("+all") || all == Some("all");
    if spoofable && score > 64 { score = 64; }
    let grade = if score >= 90 { 'A' } else if score >= 80 { 'B' } else if score >= 70 { 'C' } else if score >= 60 { 'D' } else { 'F' };
    findings.sort_by(|a, b| sev_rank(b.severity).cmp(&sev_rank(a.severity)));
    let domain = if r.domain.is_empty() { "unknown".to_string() } else { r.domain.clone() };
    AuditResult { domain, grade, score, spoofable, findings }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn to_json(res: &AuditResult) -> String {
    let mut fs = Vec::new();
    for f in &res.findings {
        fs.push(format!(
            "    {{\"severity\":\"{}\",\"record\":\"{}\",\"code\":\"{}\",\"message\":\"{}\",\"recommendation\":\"{}\"}}",
            f.severity, f.record, f.code, json_escape(&f.message), json_escape(f.recommendation)));
    }
    format!(
        "{{\n  \"domain\": \"{}\",\n  \"grade\": \"{}\",\n  \"score\": {},\n  \"spoofable\": {},\n  \"findings\": [\n{}\n  ]\n}}",
        json_escape(&res.domain), res.grade, res.score, res.spoofable, fs.join(",\n"))
}

// Tiny JSON value extractor (string fields only) so --input works without a crate.
fn json_field(text: &str, key: &str) -> String {
    let pat = format!("\"{}\"", key);
    if let Some(p) = text.find(&pat) {
        let rest = &text[p + pat.len()..];
        if let Some(c) = rest.find(':') {
            let after = rest[c + 1..].trim_start();
            if let Some(stripped) = after.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    return stripped[..end].to_string();
                }
            }
        }
    }
    String::new()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] != "audit" {
        eprintln!("usage: dmarcaudit-rs audit [--input f.json | --domain d --spf .. --dmarc .. --dkim ..]");
        exit(2);
    }
    let mut r = Records::default();
    let mut i = 1;
    while i < args.len() {
        let val = |i: &mut usize| -> String { *i += 1; args.get(*i).cloned().unwrap_or_default() };
        match args[i].as_str() {
            "--input" => {
                let path = val(&mut i);
                let text = fs::read_to_string(&path).unwrap_or_default();
                r.domain = json_field(&text, "domain");
                r.spf = json_field(&text, "spf");
                r.dmarc = json_field(&text, "dmarc");
                r.dkim = json_field(&text, "dkim");
            }
            "--domain" => r.domain = val(&mut i),
            "--spf" => r.spf = val(&mut i),
            "--dmarc" => r.dmarc = val(&mut i),
            "--dkim" => r.dkim = val(&mut i),
            _ => {}
        }
        i += 1;
    }
    let res = audit(&r);
    println!("{}", to_json(&res));
    let worst = res.findings.iter().map(|f| sev_rank(f.severity)).max().unwrap_or(0);
    if res.spoofable || worst >= sev_rank("HIGH") { exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(res: &AuditResult, code: &str) -> bool {
        res.findings.iter().any(|f| f.code == code)
    }

    #[test]
    fn test_parse_spf() {
        let s = parse_spf("v=spf1 include:_spf.google.com mx -all");
        assert!(s.present && s.valid);
        assert_eq!(s.all.as_deref(), Some("-all"));
        assert_eq!(s.lookups, 2);
        assert!(!parse_spf("not spf").present);
    }

    #[test]
    fn test_parse_dmarc() {
        let d = parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100");
        assert!(d.present);
        assert_eq!(d.tags.get("p").unwrap(), "reject");
        assert!(!parse_dmarc("").present);
    }

    #[test]
    fn test_parse_dkim_bits() {
        let d = parse_dkim("v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKW8aKnGpflynUWfpqSOUNbWjE3GEFsTIQ4CqidjPXJ+lsJilkHfRSIOk3pQ5R8azrfXZeDvahxoZSEDIqqK+NUCAwEAAQ==");
        assert!(d.present);
        assert!(d.key_bits.is_some());
    }

    #[test]
    fn test_passall_critical_and_spoofable() {
        let r = audit(&Records { domain: "bad.com".into(), spf: "v=spf1 +all".into(), ..Default::default() });
        assert!(r.spoofable);
        assert!(has(&r, "SPF_PASSALL"));
        assert_eq!(r.grade, 'F');
    }

    #[test]
    fn test_hardened_passes() {
        let dkim = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6f2qBNj811HK+iXkcVZ2RaaoAcgj8TPTokcPdMJnQPvjLpJtUc441mqtQCZNjc8F1x/G7nyRA4r+AnC/crjkLAEdJDUHROAZqc1UJJLr5FN8XwWIx4O+Zk0yw1rWgPsCwB/PwZDtLgL8YAVlRX+6ygxWjJlvy7QIka7HTcQL33Hh1XddasFdGOnixgLqRGFgImVGIRW09VerwV2xVLN7gELNDGowZWBh5OdkUeLqi/c4eG2b+AiwcmuGR3G4u8sbyXY1oHNqo7lSicUx4cYSJWZJOXJ5xDfaFv8bdd0wxyQmEyNsHsieaYpC/dhK5t/hoHB2GTqrF8fZBBuBG5S/QIDAQAB";
        let r = audit(&Records {
            domain: "good.com".into(),
            spf: "v=spf1 include:_spf.google.com -all".into(),
            dmarc: "v=DMARC1; p=reject; rua=mailto:d@good.com; pct=100".into(),
            dkim: dkim.into(),
        });
        assert!(!r.spoofable);
        assert!(r.score >= 70);
    }

    #[test]
    fn test_missing_everything() {
        let r = audit(&Records { domain: "empty.com".into(), ..Default::default() });
        assert!(r.spoofable);
        assert!(has(&r, "DMARC_MISSING") && has(&r, "SPF_MISSING"));
    }

    #[test]
    fn test_too_many_lookups() {
        let includes: Vec<String> = (0..11).map(|i| format!("include:p{}.com", i)).collect();
        let spf = format!("v=spf1 {} -all", includes.join(" "));
        let r = audit(&Records { domain: "x.com".into(), spf, dmarc: "v=DMARC1; p=reject; rua=mailto:a@x.com".into(), ..Default::default() });
        assert!(has(&r, "SPF_TOO_MANY_LOOKUPS"));
    }

    #[test]
    fn test_json_field() {
        let t = r#"{"domain":"a.com","spf":"v=spf1 -all"}"#;
        assert_eq!(json_field(t, "domain"), "a.com");
        assert_eq!(json_field(t, "spf"), "v=spf1 -all");
    }
}
