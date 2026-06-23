// Smoke tests for the JS port. Run: node test.js  (zero deps, stdlib assert)
import assert from "assert";
import { parseSpf, parseDmarc, parseDkim, audit, worstSeverity, SEVERITY_ORDER } from "./index.js";

const GOOD_DKIM = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6f2qBNj811HK+iXkcVZ2RaaoAcgj8TPTokcPdMJnQPvjLpJtUc441mqtQCZNjc8F1x/G7nyRA4r+AnC/crjkLAEdJDUHROAZqc1UJJLr5FN8XwWIx4O+Zk0yw1rWgPsCwB/PwZDtLgL8YAVlRX+6ygxWjJlvy7QIka7HTcQL33Hh1XddasFdGOnixgLqRGFgImVGIRW09VerwV2xVLN7gELNDGowZWBh5OdkUeLqi/c4eG2b+AiwcmuGR3G4u8sbyXY1oHNqo7lSicUx4cYSJWZJOXJ5xDfaFv8bdd0wxyQmEyNsHsieaYpC/dhK5t/hoHB2GTqrF8fZBBuBG5S/QIDAQAB";

const tests = {
  parse_spf() {
    const s = parseSpf("v=spf1 include:_spf.google.com mx -all");
    assert.ok(s.present && s.valid);
    assert.strictEqual(s.all, "-all");
    assert.strictEqual(s.lookups, 2);
    assert.strictEqual(parseSpf(null).present, false);
    assert.strictEqual(parseSpf("not spf").present, false);
  },
  parse_dmarc() {
    const d = parseDmarc("v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100");
    assert.ok(d.present);
    assert.strictEqual(d.tags.p, "reject");
    assert.strictEqual(d.tags.pct, "100");
    assert.strictEqual(parseDmarc(null).present, false);
  },
  parse_dkim_bits() {
    const d = parseDkim(GOOD_DKIM);
    assert.ok(d.present && d.valid);
    assert.ok([1024, 2048, 4096].includes(d.key_bits));
  },
  passall_critical() {
    const r = audit({ domain: "bad.com", spf: "v=spf1 +all" });
    assert.strictEqual(r.spoofable, true);
    assert.ok(r.findings.some((f) => f.code === "SPF_PASSALL" && f.severity === "CRITICAL"));
    assert.strictEqual(r.grade, "F");
  },
  missing_everything() {
    const r = audit({ domain: "empty.com" });
    assert.strictEqual(r.spoofable, true);
    const codes = new Set(r.findings.map((f) => f.code));
    assert.ok(codes.has("DMARC_MISSING") && codes.has("SPF_MISSING"));
  },
  hardened_passes() {
    const r = audit({
      domain: "good.com",
      spf: "v=spf1 include:_spf.google.com -all",
      dmarc: "v=DMARC1; p=reject; rua=mailto:d@good.com; pct=100",
      dkim: GOOD_DKIM,
    });
    assert.strictEqual(r.spoofable, false);
    assert.ok(r.score >= 70);
    assert.ok(["A", "B", "C"].includes(r.grade));
  },
  p_none_caps_grade() {
    const r = audit({
      domain: "monitor.com",
      spf: "v=spf1 include:_spf.google.com -all",
      dmarc: "v=DMARC1; p=none; rua=mailto:d@monitor.com",
      dkim: GOOD_DKIM,
    });
    assert.strictEqual(r.spoofable, true);
    assert.ok(r.score <= 64);
  },
  too_many_lookups() {
    const spf = "v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:p${i}.com`).join(" ") + " -all";
    const r = audit({ domain: "x.com", spf, dmarc: "v=DMARC1; p=reject; rua=mailto:a@x.com" });
    assert.ok(r.findings.some((f) => f.code === "SPF_TOO_MANY_LOOKUPS"));
  },
  weak_dkim() {
    const r = audit({ domain: "old.com", spf: "v=spf1 -all", dmarc: "v=DMARC1; p=reject; rua=mailto:a@old.com",
      dkim: "v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKW8aKnGpflynUWfpqSOUNbWjE3GEFsTIQ4CqidjPXJ+lsJilkHfRSIOk3pQ5R8azrfXZeDvahxoZSEDIqqK+NUCAwEAAQ==" });
    assert.ok(r.findings.some((f) => f.code === "DKIM_WEAK_KEY"));
  },
  worst_severity() {
    assert.strictEqual(worstSeverity([{ severity: "LOW" }, { severity: "CRITICAL" }]), "CRITICAL");
    assert.strictEqual(SEVERITY_ORDER.CRITICAL, 4);
  },
};

let pass = 0;
for (const [name, fn] of Object.entries(tests)) {
  try { fn(); pass++; console.log("PASS", name); }
  catch (e) { console.error("FAIL", name, e.message); process.exitCode = 1; }
}
console.log(`\n${pass}/${Object.keys(tests).length} JS port tests passed`);
