package main

import "testing"

func hasCode(f []Finding, code string) bool {
	for _, x := range f {
		if x.Code == code {
			return true
		}
	}
	return false
}

func TestParseSPF(t *testing.T) {
	spf := parseSPF("v=spf1 include:_spf.google.com mx -all")
	if !spf["present"].(bool) || !spf["valid"].(bool) {
		t.Fatal("expected present+valid spf")
	}
	if spf["all"].(string) != "-all" {
		t.Fatalf("all = %v", spf["all"])
	}
	if spf["lookups"].(int) != 2 {
		t.Fatalf("lookups = %v, want 2", spf["lookups"])
	}
	if parseSPF("not spf")["present"].(bool) {
		t.Fatal("garbage should not be present")
	}
}

func TestParseDMARC(t *testing.T) {
	d := parseDMARC("v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100")
	if !d["present"].(bool) {
		t.Fatal("expected present dmarc")
	}
	if d["tags"].(map[string]string)["p"] != "reject" {
		t.Fatal("p should be reject")
	}
	if parseDMARC("")["present"].(bool) {
		t.Fatal("empty dmarc not present")
	}
}

func TestParseDKIMBits(t *testing.T) {
	d := parseDKIM("v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKW8aKnGpflynUWfpqSOUNbWjE3GEFsTIQ4CqidjPXJ+lsJilkHfRSIOk3pQ5R8azrfXZeDvahxoZSEDIqqK+NUCAwEAAQ==")
	if !d["present"].(bool) {
		t.Fatal("expected present dkim")
	}
	if _, ok := d["key_bits"].(int); !ok {
		t.Fatal("expected key_bits int")
	}
}

func TestPassallCriticalAndSpoofable(t *testing.T) {
	res := audit(Records{Domain: "bad.com", SPF: "v=spf1 +all"})
	if !res.Spoofable {
		t.Fatal("expected spoofable")
	}
	if !hasCode(res.Findings, "SPF_PASSALL") {
		t.Fatal("expected SPF_PASSALL")
	}
	if res.Grade != "F" {
		t.Fatalf("grade = %s, want F", res.Grade)
	}
}

func TestHardenedPasses(t *testing.T) {
	res := audit(Records{
		Domain: "good.com",
		SPF:    "v=spf1 include:_spf.google.com -all",
		DMARC:  "v=DMARC1; p=reject; rua=mailto:d@good.com; pct=100",
		DKIM:   "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6f2qBNj811HK+iXkcVZ2RaaoAcgj8TPTokcPdMJnQPvjLpJtUc441mqtQCZNjc8F1x/G7nyRA4r+AnC/crjkLAEdJDUHROAZqc1UJJLr5FN8XwWIx4O+Zk0yw1rWgPsCwB/PwZDtLgL8YAVlRX+6ygxWjJlvy7QIka7HTcQL33Hh1XddasFdGOnixgLqRGFgImVGIRW09VerwV2xVLN7gELNDGowZWBh5OdkUeLqi/c4eG2b+AiwcmuGR3G4u8sbyXY1oHNqo7lSicUx4cYSJWZJOXJ5xDfaFv8bdd0wxyQmEyNsHsieaYpC/dhK5t/hoHB2GTqrF8fZBBuBG5S/QIDAQAB",
	})
	if res.Spoofable {
		t.Fatal("hardened domain should not be spoofable")
	}
	if res.Score < 70 {
		t.Fatalf("score = %d, want >=70", res.Score)
	}
}

func TestMissingEverything(t *testing.T) {
	res := audit(Records{Domain: "empty.com"})
	if !res.Spoofable {
		t.Fatal("expected spoofable")
	}
	if !hasCode(res.Findings, "DMARC_MISSING") || !hasCode(res.Findings, "SPF_MISSING") {
		t.Fatal("expected DMARC_MISSING and SPF_MISSING")
	}
}

func TestTooManyLookups(t *testing.T) {
	spf := "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com -all"
	res := audit(Records{Domain: "x.com", SPF: spf, DMARC: "v=DMARC1; p=reject; rua=mailto:a@x.com"})
	if !hasCode(res.Findings, "SPF_TOO_MANY_LOOKUPS") {
		t.Fatal("expected SPF_TOO_MANY_LOOKUPS")
	}
}
