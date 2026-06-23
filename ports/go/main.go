// Go port of the dmarcaudit core: parse SPF/DKIM/DMARC TXT records and grade a
// domain's email-spoofing posture. Single static binary, zero third-party deps.
// Passive by default — it grades record strings you supply (no network).
//
// Usage:
//
//	dmarcaudit-go audit --input records.json
//	dmarcaudit-go audit --domain x.com --spf "v=spf1 -all" --dmarc "v=DMARC1; p=reject"
//	echo '{"domain":"x","spf":"v=spf1 +all"}' | dmarcaudit-go audit -
//
// Exit code is non-zero when the domain is spoofable or has a HIGH+ finding,
// matching the Python reference, so it drops into CI the same way.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var sevOrder = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

// Finding mirrors the Python dataclass field-for-field (snake_case JSON).
type Finding struct {
	Severity       string `json:"severity"`
	Record         string `json:"record"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

type Result struct {
	Domain    string                 `json:"domain"`
	Grade     string                 `json:"grade"`
	Score     int                    `json:"score"`
	Spoofable bool                   `json:"spoofable"`
	SPF       map[string]interface{} `json:"spf"`
	DMARC     map[string]interface{} `json:"dmarc"`
	DKIM      map[string]interface{} `json:"dkim"`
	Findings  []Finding              `json:"findings"`
}

type Records struct {
	Domain string `json:"domain"`
	SPF    string `json:"spf"`
	DMARC  string `json:"dmarc"`
	DKIM   string `json:"dkim"`
}

func parseSPF(rec string) map[string]interface{} {
	out := map[string]interface{}{"present": false, "raw": rec, "all": nil,
		"mechanisms": []string{}, "lookups": 0, "redirect": nil, "valid": false}
	rec = strings.Trim(strings.TrimSpace(rec), "\"")
	if rec == "" || !strings.HasPrefix(strings.ToLower(rec), "v=spf1") {
		return out
	}
	out["present"] = true
	out["valid"] = true
	toks := strings.Fields(rec)[1:]
	lookups := 0
	mechs := []string{}
	for _, tok := range toks {
		low := strings.ToLower(tok)
		switch low {
		case "+all", "-all", "~all", "?all":
			out["all"] = low
			continue
		case "all":
			out["all"] = "+all"
			continue
		}
		if strings.HasPrefix(low, "redirect=") {
			out["redirect"] = tok[len("redirect="):]
			lookups++
			continue
		}
		mechs = append(mechs, tok)
		if strings.HasPrefix(low, "include:") || strings.HasPrefix(low, "exists:") ||
			low == "a" || low == "mx" || low == "ptr" ||
			strings.HasPrefix(low, "a:") || strings.HasPrefix(low, "mx:") ||
			strings.HasPrefix(low, "a/") || strings.HasPrefix(low, "mx/") {
			lookups++
		}
	}
	out["mechanisms"] = mechs
	out["lookups"] = lookups
	return out
}

func parseTagged(rec, version string) (map[string]string, bool) {
	tags := map[string]string{}
	rec = strings.Trim(strings.TrimSpace(rec), "\"")
	if rec == "" || !strings.HasPrefix(strings.ToLower(rec), version) {
		return tags, false
	}
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return tags, true
}

func parseDMARC(rec string) map[string]interface{} {
	tags, present := parseTagged(rec, "v=dmarc1")
	return map[string]interface{}{"present": present, "raw": rec, "tags": tags, "valid": present}
}

var wsRe = regexp.MustCompile(`\s+`)

func parseDKIM(rec string) map[string]interface{} {
	out := map[string]interface{}{"present": false, "raw": rec, "tags": map[string]string{},
		"valid": false, "key_bits": nil}
	r := strings.Trim(strings.TrimSpace(rec), "\"")
	low := strings.ToLower(r)
	if r == "" || (!strings.Contains(low, "p=") && !strings.Contains(low, "v=dkim1")) {
		return out
	}
	out["present"] = true
	tags := map[string]string{}
	for _, part := range strings.Split(r, ";") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	out["tags"] = tags
	pub := tags["p"]
	out["valid"] = pub != ""
	if pub != "" {
		derLen := int(float64(len(wsRe.ReplaceAllString(pub, ""))) * 3 / 4)
		switch {
		case derLen >= 380:
			out["key_bits"] = 4096
		case derLen >= 250:
			out["key_bits"] = 2048
		case derLen >= 120:
			out["key_bits"] = 1024
		default:
			out["key_bits"] = 512
		}
	}
	return out
}

func add(f *[]Finding, sev, rec, code, msg, fix string) {
	*f = append(*f, Finding{sev, rec, code, msg, fix})
}

func gradeSPF(spf map[string]interface{}, f *[]Finding) int {
	if !spf["present"].(bool) {
		add(f, "HIGH", "SPF", "SPF_MISSING", "No SPF record found.",
			"Publish v=spf1 include:<provider> -all")
		return 0
	}
	pts := 20
	all, _ := spf["all"].(string)
	switch all {
	case "-all":
		pts += 20
	case "~all":
		pts += 12
		add(f, "MEDIUM", "SPF", "SPF_SOFTFAIL", "SPF ends in ~all (softfail).",
			"Move to -all once senders are confirmed.")
	case "+all", "all":
		add(f, "CRITICAL", "SPF", "SPF_PASSALL",
			"SPF ends in +all — any host passes SPF. Trivially spoofable.",
			"Replace +all with -all immediately.")
	case "?all":
		pts += 4
		add(f, "HIGH", "SPF", "SPF_NEUTRAL", "SPF ends in ?all (neutral).", "Use -all.")
	default:
		add(f, "MEDIUM", "SPF", "SPF_NO_ALL", "SPF has no 'all' mechanism.", "Append -all.")
	}
	if spf["lookups"].(int) > 10 {
		add(f, "HIGH", "SPF", "SPF_TOO_MANY_LOOKUPS",
			fmt.Sprintf("SPF requires %d DNS lookups (limit 10).", spf["lookups"].(int)),
			"Flatten includes to <=10 lookups.")
		pts -= 10
	}
	if pts < 0 {
		pts = 0
	}
	return pts
}

func gradeDMARC(dmarc map[string]interface{}, f *[]Finding) int {
	if !dmarc["present"].(bool) {
		add(f, "CRITICAL", "DMARC", "DMARC_MISSING", "No DMARC record at _dmarc.<domain>.",
			"Publish v=DMARC1; p=quarantine; rua=mailto:...")
		return 0
	}
	pts := 15
	tags := dmarc["tags"].(map[string]string)
	policy := strings.ToLower(tags["p"])
	if policy == "" {
		policy = "none"
	}
	switch policy {
	case "reject":
		pts += 25
	case "quarantine":
		pts += 15
		add(f, "LOW", "DMARC", "DMARC_QUARANTINE", "DMARC policy is p=quarantine.",
			"Move to p=reject when reports are clean.")
	default:
		add(f, "HIGH", "DMARC", "DMARC_POLICY_NONE", "DMARC policy is p=none (monitor only).",
			"Tighten to p=quarantine then p=reject.")
	}
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil && n < 100 {
			add(f, "MEDIUM", "DMARC", "DMARC_PARTIAL_PCT",
				fmt.Sprintf("DMARC pct=%s — applies to only %s%% of mail.", pct, pct),
				"Set pct=100.")
			pts -= 5
		}
	}
	if sp, ok := tags["sp"]; ok && strings.ToLower(sp) == "none" && policy != "none" {
		add(f, "MEDIUM", "DMARC", "DMARC_SUBDOMAIN_NONE", "Subdomain policy sp=none weakens protection.",
			"Remove sp=none or set sp=reject.")
		pts -= 5
	}
	if tags["rua"] == "" {
		add(f, "LOW", "DMARC", "DMARC_NO_RUA", "No aggregate report address (rua).",
			"Add rua=mailto:dmarc-reports@<domain>.")
	}
	if strings.ToLower(tags["aspf"]) == "s" || strings.ToLower(tags["adkim"]) == "s" {
		pts += 3
	}
	if pts < 0 {
		pts = 0
	}
	return pts
}

func gradeDKIM(dkim map[string]interface{}, f *[]Finding) int {
	if !dkim["present"].(bool) {
		add(f, "MEDIUM", "DKIM", "DKIM_MISSING", "No DKIM record for the supplied selector.",
			"Enable DKIM signing and publish the public key.")
		return 0
	}
	pts := 15
	if bits, ok := dkim["key_bits"].(int); ok {
		switch {
		case bits < 1024:
			add(f, "CRITICAL", "DKIM", "DKIM_WEAK_KEY",
				fmt.Sprintf("DKIM key appears to be %d-bit — forgeable.", bits),
				"Rotate to a 2048-bit RSA key.")
		case bits < 2048:
			add(f, "MEDIUM", "DKIM", "DKIM_1024_KEY", "DKIM key is ~1024-bit (deprecated).",
				"Rotate to a 2048-bit RSA key.")
		default:
			pts += 5
		}
	}
	tags := dkim["tags"].(map[string]string)
	if strings.Contains(strings.ToLower(tags["t"]), "y") {
		add(f, "LOW", "DKIM", "DKIM_TESTING", "DKIM record is in testing mode (t=y).",
			"Remove t=y once signing is verified.")
	}
	return pts
}

func audit(r Records) Result {
	spf := parseSPF(r.SPF)
	dmarc := parseDMARC(r.DMARC)
	dkim := parseDKIM(r.DKIM)
	findings := []Finding{}
	score := gradeSPF(spf, &findings) + gradeDMARC(dmarc, &findings) + gradeDKIM(dkim, &findings)
	if score > 100 {
		score = 100
	}
	policy := "none"
	if dmarc["present"].(bool) {
		if p, ok := dmarc["tags"].(map[string]string)["p"]; ok && p != "" {
			policy = strings.ToLower(p)
		}
	}
	all, _ := spf["all"].(string)
	enforced := dmarc["present"].(bool) && (policy == "quarantine" || policy == "reject")
	spoofable := !enforced || all == "+all" || all == "all"
	if spoofable && score > 64 {
		score = 64
	}
	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	}
	// sort findings worst-first (stable insertion order within a severity)
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && sevOrder[findings[j].Severity] > sevOrder[findings[j-1].Severity]; j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
	domain := r.Domain
	if domain == "" {
		domain = "unknown"
	}
	return Result{domain, grade, score, spoofable, spf, dmarc, dkim, findings}
}

func worst(f []Finding) string {
	w := "INFO"
	for _, x := range f {
		if sevOrder[x.Severity] > sevOrder[w] {
			w = x.Severity
		}
	}
	return w
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dmarcaudit-go audit [--input f.json | --domain d --spf .. --dmarc .. --dkim ..] [-]")
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] != "audit" {
		usage()
		os.Exit(2)
	}
	var r Records
	gotStdin := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch a {
		case "--input":
			b, err := os.ReadFile(next())
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(2)
			}
			json.Unmarshal(b, &r)
		case "--domain":
			r.Domain = next()
		case "--spf":
			r.SPF = next()
		case "--dmarc":
			r.DMARC = next()
		case "--dkim":
			r.DKIM = next()
		case "-":
			gotStdin = true
		}
	}
	if gotStdin {
		b, _ := io.ReadAll(os.Stdin)
		json.Unmarshal(b, &r)
	}
	res := audit(r)
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if res.Spoofable || sevOrder[worst(res.Findings)] >= sevOrder["HIGH"] {
		os.Exit(1)
	}
}
