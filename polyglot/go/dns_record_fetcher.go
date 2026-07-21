package dnsrecordfetcher

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	defaultTimeout    = 10 * time.Second
	defaultRetries    = 3
	dmarcSelector     = "_dmarc"
	spfSelector       = "default"
	dkimSelector      = "selector1" // Try selector1 first, then others
	dkimSelectors     = []string{"selector1", "selector2", "selector3"}
)

// RecordType represents the type of DNS record to fetch.
type RecordType string

const (
	TypeMX  RecordType = "MX"
	TypeTXT RecordType = "TXT"
)

// FetchResult holds the result of a single DNS query.
type FetchResult struct {
	RecordType    RecordType
	Domain        string
	Records       []string
	Error         error
	Truncated     bool
	TTL           uint32
}

// DMARCAuditResult contains parsed and analyzed DMARC data.
type DMARCAuditResult struct {
	// Raw records fetched
	MXRecords    []string
	TXTRecords   []string
	
	// Parsed policies
	SPFValid     bool
	SPFRecord    string
	DKIMKeys     []DKIMKeyInfo
	DKIMValid    bool
	DKIMSelector  string
	DKIMDomain    string
	DKIMEncoding  string // base64 or publickey
	
	DMARCPolicy   DMARCPolicy
	DMARCValid    bool
	DMARCSel      string
	
	// Overall assessment
	Spoofable     bool
	PriorityFixes []string
}

// DKIMKeyInfo represents a parsed DKIM key.
type DKIMKeyInfo struct {
	KeyType   string // "rsa" or "ecdsa"
	Algorithm string // e.g., "rsa-sha256", "rsa-sha1"
	Version   int    // 1, 2, etc.
	Encoding  string // base64, publickey, pem
	Key       string
}

// DMARCPolicy represents a parsed DMARC policy.
type DMARCPolicy struct {
	Priority  string // "p=none", "p=quarantine", "p=reject"
	Tag       string // "tag=something" or "tag=value"
	Selector  string
	RawRecord string
}

// Config holds configuration for DNS fetching.
type Config struct {
	DNSServers []string
	Timeout    time.Duration
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		DNSServers: nil, // Use system defaults
		Timeout:    defaultTimeout,
	}
}

// FetchMXRecords fetches MX records for the given domain.
func FetchMXRecords(ctx context.Context, domain string) ([]string, error) {
	mxRRSet, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup MX: %w", err)
	}
	
	var records []string
	for _, mx := range mxRRSet {
		records = append(records, mx.String())
	}
	
	return records, nil
}

// FetchTXTRecords fetches TXT records for the given domain.
func FetchTXTRecords(ctx context.Context, domain string) ([]string, error) {
	txtRRSet, err := net.LookupTXT(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup TXT: %w", err)
	}
	
	var records []string
	for _, txt := range txtRRSet {
		records = append(records, txt)
	}
	
	return records, nil
}

// FetchTXTRecordsWithSelector fetches TXT records for a specific selector.
func FetchTXTRecordsWithSelector(ctx context.Context, domain, selector string) ([]string, error) {
	fullDomain := fmt.Sprintf("%s.%s", selector, dmarcSelector)
	if fullDomain != selector {
		fullDomain = fmt.Sprintf("_%s.%s", selector, domain)
	} else if !strings.Contains(selector, "_") && !strings.Contains(selector, ".") {
		fullDomain = fmt.Sprintf("_%s._dmarc.%s", selector, domain)
	} else {
		fullDomain = fmt.Sprintf("%s._dmarc.%s", selector, domain)
	}
	
	return FetchTXTRecords(ctx, fullDomain)
}

// ParseSPFRecord parses and validates an SPF record.
func ParseSPFRecord(record string) (bool, string, error) {
	record = strings.TrimSpace(record)
	if len(record) == 0 || record[0] != 'v' || !strings.HasPrefix(strings.ToLower(record), "spf1") {
		return false, "", nil
	}
	
	var valid bool
	for _, part := range strings.Fields(record) {
		switch part[:4] {
		case "v=spf1":
			continue
		case "all", "ip4:", "ip6:", "include:", "redirect=", "a:", "mx:", 
			 "exists:", "ptr:", "tag=", "exp:":
			valid = true
		default:
			return false, "", fmt.Errorf("unknown SPF tag: %s", part)
		}
	}
	
	return valid, record, nil
}

// ParseDKIMKeyInfo parses a DKIM public key from a TXT record.
func ParseDKIMKeyInfo(record string) (*DKIMKeyInfo, error) {
	record = strings.TrimSpace(record)
	if len(record) == 0 || !strings.HasPrefix(strings.ToLower(record), "v=dkim1") {
		return nil, nil
	}
	
	parts := strings.FieldsFunc(record, func(r rune) bool { return r == ' ' })
	var keyType, algorithm string
	
	for _, part := range parts {
		switch {
		case part[:4] == "v=dkim1":
			continue
		case part[:5] == "k=rsa", part[:6] == "k=ecdsa":
			keyType = strings.TrimPrefix(part, "k=")
		case part[:7] == "a=rsa-sha256", part[:8] == "a=rsa-sha1", 
			 part[:9] == "a=rsa-sha512", part[:8] == "a=ecc-sha256":
			algorithm = strings.TrimPrefix(part, "a=")
		case part[:7] == "t=_dmarc", part[:6] == "h=sha256", 
			 part[:4] == "p=", part[:8] == "b64=", part[:10] == "pem:":
			continue // Skip metadata fields
		case strings.HasPrefix(part, "p="):
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace(parts[1]),
				}, nil
			}
		case part[:5] == "b64=" || part[:7] == "pem:" || part[:8] == "publickey":
			parts := strings.SplitN(strings.TrimPrefix(part, "p="), "=", 2)
			if len(parts) == 2 {
				return &DKIMKeyInfo{
					KeyType:   keyType,
					Algorithm: algorithm,
					Version:   1,
					Encoding:  parts[0],
					Key:       strings.TrimSpace