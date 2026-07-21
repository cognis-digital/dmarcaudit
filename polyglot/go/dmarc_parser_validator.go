package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/dns"
	"os"
	"strings"
	"time"
)

// DMARCRecord represents a parsed DMARC DNS record
type DMARCRecord struct {
	Version   string `json:"version"`
	Policy    string `json:"policy"`
	SubPolicy string `json:"sub_policy,omitempty"`
	RU        string `json:"ru,omitempty"`
}

// SPFRecord represents a parsed SPF DNS record
type SPFRecord struct {
	Version  string
	HardFail bool
	SoftFail bool
	Includes []string
	MaxHosts int
}

// DKIMKeyInfo holds information about a found DKIM key
type DKIMKeyInfo struct {
	Selector    string
	Algorithm   string
	KeyLength   int
	Valid       bool
}

// AuditResult is the complete audit output
type AuditResult struct {
	Domain        string     `json:"domain"`
	Timestamp     time.Time  `json:"timestamp"`
	DMARC         DMARCRecord `json:"dmarc,omitempty"`
	SPF           SPFRecord   `json:"spf,omitempty"`
	DKIM          DKIMKeyInfo `json:"dkim,omitempty"`
	Spoofability  int        `json:"spoofability_score"` // 0-100, higher = more spoofable
	Findings      []Finding  `json:"findings"`
	Fixes         []Fix       `json:"fixes"`
}

// Finding represents a specific issue found
type Finding struct {
	Type    string   `json:"type"`
	Priority int      `json:"priority"` // 1-5, 1 is most critical
	Message string   `json:"message"`
	Details string   `json:"details,omitempty"`
}

// Fix represents a recommended action
type Fix struct {
	Priority    int      `json:"priority"`
	Description string   `json:"description"`
	Command     string   `json:"command,omitempty"`
}

const (
	dmarcSelector = "_dmarc"
	spfxSelector  = "default._spf" // Common SPF selector
	defaultTTL    = 30 * time.Second
)

// DNSConfig holds resolver configuration
type DNSConfig struct {
	Timeout   time.Duration
	RetryTime time.Duration
}

func NewDNSConfig() DNSConfig {
	return DNSConfig{
		Timeout:   5 * time.Second,
		RetryTime: 100 * time.Millisecond,
	}
}

// QueryDMARC fetches and parses the DMARC record for a domain
func QueryDMARC(ctx context.Context, domain string) (*DMARCRecord, error) {
	c := new(dns.Client)
	c.Timeout = defaultTTL

	name := fmt.Sprintf("%s.%s", dmarcSelector, domain)
	mx := dns.Msg{
		Header: dns.Header{
			Name:  name,
			Qclass: dns.TypeTXT,
			Qcount: 1,
		},
	}

	resp, err := c.Exchange(&mx, ctx, "8.8.8.8")
	if err != nil {
		return nil, fmt.Errorf("DNS exchange failed: %w", err)
	}

	var records []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, txt.Txt...)
		}
	}

	return parseDMARCRecords(records), nil
}

// QuerySPF fetches and parses the SPF record for a domain
func QuerySPF(ctx context.Context, domain string) (*SPFRecord, error) {
	c := new(dns.Client)
	c.Timeout = defaultTTL

	name := fmt.Sprintf("%s.%s", spfxSelector, domain)
	mx := dns.Msg{
		Header: dns.Header{
			Name:  name,
			Qclass: dns.TypeTXT,
			Qcount: 1,
		},
	}

	resp, err := c.Exchange(&mx, ctx, "8.8.8.8")
	if err != nil {
		return nil, fmt.Errorf("DNS exchange failed: %w", err)
	}

	var records []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, txt.Txt...)
		}
	}

	return parseSPFRecords(records), nil
}

// QueryDKIM fetches the DKIM public key for a domain
func QueryDKIM(ctx context.Context, domain string) (*DKIMKeyInfo, error) {
	c := new(dns.Client)
	c.Timeout = defaultTTL

	name := fmt.Sprintf("%s.%s", dmarcSelector, domain)
	mx := dns.Msg{
		Header: dns.Header{
			Name:  name,
			Qclass: dns.TypeTXT,
			Qcount: 1,
		},
	}

	resp, err := c.Exchange(&mx, ctx, "8.8.8.8")
	if err != nil {
		return nil, fmt.Errorf("DNS exchange failed: %w", err)
	}

	var records []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, txt.Txt...)
		}
	}

	return parseDKIMRecords(records), nil
}

// parseDMARCRecords parses multiple DMARC TXT records into a structured record
func parseDMARCRecords(records []string) *DMARCRecord {
	result := &DMARCRecord{Version: "v1"}

	for _, r := range records {
		r = strings.TrimSpace(r)
		if !strings.HasPrefix(r, "v=") || len(r) < 3 {
			continue
		}

		parts := strings.SplitN(r[2:], ",", 3)
		result.Version = parts[0]

		if len(parts) > 1 && parts[1] != "" {
			result.Policy = parts[1]
		}

		if len(parts) > 2 && parts[2] != "" {
			result.SubPolicy = parts[2]
		}

		if result.Version == "v1" || result.Version == "v=1" {
			break
		}
	}

	return result
}

// parseSPFRecords parses SPF records and extracts key attributes
func parseSPFRecords(records []string) *SPFRecord {
	result := &SPFRecord{Version: "v1"}

	for _, r := range records {
		r = strings.TrimSpace(r)
		if !strings.HasPrefix(r, "v=") || len(r) < 3 {
			continue
		}

		parts := strings.SplitN(r[2:], ",", 5)
		result.Version = parts[0]

		if len(parts) > 1 && parts[1] != "" {
			result.HardFail = parts[1] == "hard" || parts[1] == "h"
		}

		if len(parts) > 2 && parts[2] != "" {
			result.SoftFail = parts[2] == "soft" || parts[2] == "s"
		}

		for _, include := range parts[3:] {
			if strings.HasPrefix(include, "include:") {
				result.Includes = append(result.Includes, strings.TrimPrefix(include, "include:"))
			} else if strings.HasPrefix(include, "a") || strings.HasPrefix(include, "i") {
				result.MaxHosts = 10 // Default for a/i includes
			}
		}

		if result.Version == "v1" || result.Version == "v=1" {
			break
		}
	}

	return result
}

// parseDKIMRecords parses DKIM records and extracts key info
func parseDKIMRecords(records []string) *DKIMKeyInfo {
	result := &DKIMKeyInfo{Selector: dmarcSelector, Valid: false}

	for _, r := range records {
		r = strings.TrimSpace(r)
		if !strings.HasPrefix(r, "v=") || len(r) < 3 {
			continue
		}

		parts := strings.SplitN(r[2:], ",", 4)
		result.Selector = parts[0]

		if len(parts) > 1 && parts[1] != "" {
			result.Algorithm = parts[1]
		}

		if len(parts) > 2 && parts[2] != "" {
			keyLen := len([]rune(parts[2]))
			result.KeyLength = keyLen
			result.Valid = result.KeyLength >= 500 // Minimum reasonable length
		}

		if result.Algorithm == "rsa" || result.Algorithm == "rsa1" {
			result.Valid = true
		} else if strings.HasPrefix(result.Algorithm, "rsa") {
			result.Valid = true
		}

		if result.Valid {
			break
		}
	}

	return result
}

// CalculateSpoofability computes a 0-100 score where higher means more spoofable
func CalculateSpoofability(domain string, dmarc *DMARCRecord, spf *SPFRecord, dkim *DKIMKeyInfo) int {
	score := 50 // Base score - medium risk

	// DMARC factors (weight: 40%)
	dmarcScore := calculateDMARCScore(dmarc)
	score += dmarcScore * 40 / 100

	// SPF factors (weight: 30%)
	spfScore := calculateSPFScore(spf)
	score += spfScore * 30 / 100

	// DKIM factors (weight: 30%)
	dkimScore := calculateDKIMScore(dkim)
	score += dkimScore * 30 / 100

	return score
}

func calculateDMARCScore(r *DMARCRecord) int {
	if r == nil || r.Version != "v1" && r.Version != "v=1" {
		return 50 // No record = medium risk
	}

	score := 50

	// Check policy strength
	switch strings.ToLower(r.Policy) {
	case "p=none", "p=none;ru=":
		score -= 20
	case "p=quarantine":
		score -= 10
	case "p=reject", "p=reject;ru=":
		score += 15
	default:
		score -= 5
	}

	// Check sub-policy (RU) presence
	if r.SubPolicy != "" {
		score += 5 // Good practice to have RU
	}

	return max(0, min(100, score))
}

func calculateSPFScore(r *SPFRecord) int {
	if r == nil || r.Version != "v1" && r.Version != "v=1" {
		return 50 // No record = medium risk
	}

	score := 50

	// Check hard fail (most secure)
	if r.HardFail {
		score += 20
	} else if r.SoftFail {
		score += 10
	} else {
		score -= 10
	}

	// Penalize too many includes (potential for expansion attacks)
	if len(r.Includes) > 3 {
		score -= 5 * (len(r.Includes) - 3)
	}

	return max(0, min(100, score))
}

func calculateDKIMScore(r *DKIMKeyInfo) int {
	if r == nil || !r.Valid {
		return 25 // No valid key = high risk
	}

	score := 75

	// Longer keys are better (up to a point)
	if r.KeyLength < 1000 {
		score -= 10 * (1000 - r.KeyLength) / 1000
	}

	return max(0, min(100, score))
}

// GenerateFixes creates prioritized fix recommendations
func GenerateFixes(domain string, result *AuditResult) []Fix {
	var fixes []Fix

	if !result.DKIM.Valid {
		fixes = append(fixes, Fix{
			Priority:    1,
			Description: "Configure DKIM signing for the domain",
			Command:     fmt.Sprintf("dkim-keygen -n %s -d %s -a rsa256", dmarcSelector, domain),
		})
	}

	if result.DKIM.Valid && !result.DKIM.KeyLength >= 1000 {
		fixes = append(fixes, Fix{
			Priority:    2,
			Description: "Regenerate DKIM key with longer length (min 1000 chars)",
		})
	}

	if result.DMARC.Policy == "" || strings.Contains(strings.ToLower(result.DMARC.Policy), "none") {
		fixes = append(fixes, Fix{
			Priority:    3,
			Description: "Set DMARC policy to 'quarantine' or 'reject'",
			Command:     fmt.Sprintf("dig TXT %s.%s | grep -oP 'v=1\\K[^;]+'", dmarcSelector, domain),
		})
	}

	if result.SPF.HardFail {
		fixes = append(fixes, Fix{
			Priority:    4,
			Description: "SPF is configured with hard fail - verify all includes are trusted",
		})
	} else if !result.SPF.HardFail && !result.SPF.SoftFail {
		fixes = append(fixes, Fix{
			Priority:    5,
			Description: "Consider upgrading SPF from soft to hard fail for stronger protection",
		})
	}

	return fixes
}

// RunAudit performs a complete DMARC/SPF/DKIM audit
func RunAudit(ctx context.Context, domain string) (*AuditResult, error) {
	dmarc, err := QueryDMARC(ctx, domain)
	if err != nil {
		return &AuditResult{Domain: domain, Findings: []Finding{{Type: "error", Priority: 1, Message: fmt.Sprintf("DMARC query failed: %v", err}}}, Spoofability: 75}, err
	}

	spf, err := QuerySPF(ctx, domain)
	if err != nil {
		return &AuditResult{Domain: domain, Findings: []Finding{{Type: "error", Priority: 1, Message: fmt.Sprintf("SPF query failed: %v", err}}}, Spoofability: 75}, err
	}

	dkim, err := QueryDKIM(ctx, domain)
	if err != nil {
		return &AuditResult{Domain: domain, Findings: []Finding{{Type: "error", Priority: 1, Message: fmt.Sprintf("DKIM query failed: %v", err}}}, Spoofability: 75}, err
	}

	result := &AuditResult{
		Domain:   domain,
		Timestamp: time.Now(),
		DMARC:    *dmarc,
		SPF:      *spf,
		DKIM:     *dkim,
		Spoofability: CalculateSpoofability(domain, dmarc, spf, dkim),
	}

	result.Findings = generateFindings(result)
	result.Fixes = GenerateFixes(domain, result)

	return result, nil
}

// generateFindings creates detailed findings based on audit results
func generateFindings(r *AuditResult) []Finding {
	var findings []Finding

	if r.DMARC.Version != "v1" && r.DMARC.Version != "v=1" {
		findings = append(findings, Finding{
			Type:    "warning",
			Priority: 2,
			Message: "DMARC record not found or malformed",
			Details: "Add a DMARC TXT record at _dmarc.<domain> with v=1 policy",
		})
	} else if r.DMARC.Policy == "" {
		findings = append(findings, Finding{
			Type:    "warning",
			Priority: 2,
			Message: "DMARC record found but missing policy directive",
			Details: "Include a policy (p=none/quarantine/reject) in the DMARC record",
		})
	} else if strings.Contains(strings.ToLower(r.DMARC.Policy), "reject") {
		findings = append(findings, Finding{
			Type:    "info",
			Priority: 3,
			Message: "DMARC policy set to reject - strong protection enabled",
		})
	}

	if r.SPF.Version != "v1" && r.SPF.Version != "v=1" {
		findings = append(findings, Finding{
			Type:    "warning",
			Priority: 2,
			Message: "SPF record not found or malformed",
			Details