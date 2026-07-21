import { DomainAuditResult, DMARCParsed, SPFParsed, DKIMParsed, FixPriority, AuditReport } from './types';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export interface DNSRecord {
  name: string;
  type: 'TXT' | 'SPF' | 'DKIM' | 'DMARC' | 'OTHER';
  ttl?: number;
  content: string[];
}

export interface DMARCParsed extends DMARCParsedBase {
  rua: string[];
  ruf: string[];
  adkim: string;
  aspf: string;
  sp: string;
  pct: number | 'all' | 'none';
  id: string;
}

export interface SPFParsed extends SPFBase {
  mechanisms: MechanismCount;
  authRate: number;
  hasInclude: boolean;
  includeDomains: string[];
  commonIssues: SPFCommonIssue[];
}

export interface DKIMParsed {
  selectors: DKIMSelectorInfo[];
  hasPublicKey: boolean;
  keyLength: number | null;
  algorithm: string | null;
  issues: DKIMIssue[];
}

export interface MechanismCount {
  all: number;
  ip4: number;
  ip6: number;
  mx: number;
  a: number;
  ptr: number;
  include: number;
  other: number;
}

export interface SPFBase {
  version: string | null;
  hasAll: boolean;
  maxAuthRate: number | null;
  redirectDomain: string | null;
  tempFailure: string | null;
  permanentFailure: string | null;
}

export interface SPFCommonIssue {
  type: 'MAX_AUTH_RATE' | 'REDIRECT_DOMAIN' | 'TEMP_FAILURE' | 'PERM_FAILURE';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface DKIMSelectorInfo {
  selector: string;
  publicKey: string;
  keyLength: number;
  algorithm: string | null;
  validFormat: boolean;
}

export interface DKIMIssue {
  type: 'NO_PUBLIC_KEY' | 'SHORT_KEY' | 'UNUSUAL_ALGORITHM';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface DMARCParsedBase {
  version: string | null;
  hasAll: boolean;
  maxAuthRate: number | null;
  rua: string[];
  ruf: string[];
  adkim: string;
  aspf: string;
  sp: string;
  pct: number | 'all' | 'none';
  id: string;
}

export interface AuditReport {
  domain: string;
  timestamp: Date;
  dnsRecords: DNSRecord[];
  dmarc: DMARCParsed | null;
  spf: SPFParsed | null;
  dkim: DKIMParsed | null;
  spoofabilityScore: number; // 0-100, higher = more spoofable
  spoofabilityLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  prioritizedFixes: FixPriority[];
  summary: string;
}

export interface FixPriority {
  priority: 1 | 2 | 3 | 4 | 5; // 1 = most urgent
  category: 'DMARC' | 'SPF' | 'DKIM' | 'GENERAL';
  title: string;
  description: string;
  impact: number; // 1-10, higher = more impact
  effort: number; // 1-5, lower = easier to fix
  command?: string;
}

// ============================================================================
// CONSTANTS & PATTERN MATCHERS
// ============================================================================

const DMARC_VERSION_REGEX = /^v=DMARC1\.(?<version>\d+)/;
const SPF_VERSION_REGEX = /^v=spf1(?<rest>.*)$/;
const DMARC_ALL_REGEX = /\ball\b/i;
const SPF_ALL_REGEX = /\ball\b/i;
const SPF_MAX_AUTH_RATE_REGEX = /maxauthrate=(?<rate>[0-9.]+)/i;
const SPF_REDIRECT_DOMAIN_REGEX = /redirectdomain=(?<domain>.+)/i;
const SPF_TEMP_FAILURE_REGEX = /tempfail=(?<value>.+)/i;
const SPF_PERM_FAILURE_REGEX = /permfail=(?<value>.+)/i;

// DKIM key length thresholds (in bits)
const DKIM_SHORT_KEY_THRESHOLD = 1024; // RSA-1024 minimum, 2048 recommended
const DKIM_RECOMMENDED_LENGTH = 2048;

// ============================================================================
// DMARC PARSERS & VALIDATORS
// ============================================================================

export function parseDMARC(content: string): DMARCParsed | null {
  if (!content || !content.trim()) return null;

  const lines = content.split('\n').map(l => l.trim()).filter(l => l);
  
  // Must start with version tag
  if (!lines[0].match(DMARC_VERSION_REGEX)) {
    return {
      version: '1.0',
      hasAll: false,
      maxAuthRate: null,
      rua: [],
      ruf: [],
      adkim: 'relaxed',
      aspf: 'relaxed',
      sp: 'none',
      pct: 100,
      id: '',
    };
  }

  const match = lines[0].match(DMARC_VERSION_REGEX);
  const version = match?.groups?.version || '1.0';

  // Parse all parameters
  const params: Record<string, string> = {};
  
  for (const line of lines) {
    const parts = line.split('=');
    if (parts.length < 2) continue;
    
    let key = parts[0].trim().toLowerCase();
    let value = parts.slice(1).join('=').trim();
    
    // Handle quoted values
    if ((value.startsWith('"') && value.endsWith('"')) || 
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    params[key] = value;
  }

  const rua: string[] = [];
  const ruf: string[] = [];
  
  if (params.rua) {
    rua.push(...params.rua.split(','));
  }
  if (params.ruf) {
    ruf.push(...params.ruf.split(','));
  }

  return {
    version,
    hasAll: DMARC_ALL_REGEX.test(content),
    maxAuthRate: params.pct ? parseFloat(params.pct) : 100,
    rua,
    ruf,
    adkim: params.adkim || 'relaxed',
    aspf: params.aspf || 'relaxed',
    sp: params.sp || 'none',
    pct: params.pct ? (parseFloat(params.pct) === 100 ? 'all' : parseFloat(params.pct)) : 100,
    id: params.id || '',
  };
}

export function validateDMARC(parsed: DMARCParsed | null): string[] {
  const issues: string[] = [];

  if (!parsed) {
    issues.push('No DMARC record found');
    return issues;
  }

  // Check for proper version
  if (parsed.version !== '1.0') {
    issues.push(`Unexpected DMARC version: ${parsed.version}`);
  }

  // Check rua - at least one required for full compliance
  if (parsed.rua.length === 0) {
    issues.push('Missing rua tag - no reporting destination configured');
  } else if (parsed.rua.some(r => !r.match(/^[a-zA-Z0-9+.-]+:[a-zA-Z0-9+.-]+$/))) {
    issues.push('Invalid rua format - should be email:port or email');
  }

  // Check ruf - optional but recommended
  if (parsed.ruf.length === 0) {
    issues.push('Missing ruf tag - failure reporting not configured');
  }

  // Check sp - should be none, quarantine, or reject
  const validSP = ['none', 'quarantine', 'reject'];
  if (!validSP.includes(parsed.sp.toLowerCase())) {
    issues.push(`Invalid sp value: ${parsed.sp}`);
  }

  // Check pct - should be 0-100 or 'all'
  if (parsed.pct !== 'all' && 
      (typeof parsed.pct === 'number' ? parsed.pct < 0 || parsed.pct > 100 : true)) {
    issues.push('Invalid pct value - should be 0-100 or "all"');
  }

  // Check adkim/aspf - should be relaxed or strict
  const validPolicy = ['relaxed', 'strict'];
  if (!validPolicy.includes(parsed.adkim.toLowerCase())) {
    issues.push(`Invalid adkim value: ${parsed.adkim}`);
  }
  if (!validPolicy.includes(parsed.aspf.toLowerCase())) {
    issues.push(`Invalid aspf value: ${parsed.aspf}`);
  }

  return issues;
}

// ============================================================================
// SPF PARSERS & VALIDATORS
// ============================================================================

export function parseSPF(content: string): SPFParsed | null {
  if (!content || !content.trim()) return null;

  const match = content.match(SPF_VERSION_REGEX);
  const rest = match?.groups?.rest || '';

  // Parse mechanisms
  const mechanisms: MechanismCount = {
    all: 0,
    ip4: 0,
    ip6: 0,
    mx: 0,
    a: 0,
    ptr: 0,
    include: 0,
    other: 0,
  };

  // Parse special tags
  const hasAll = SPF_ALL_REGEX.test(content);
  let maxAuthRate: number | null = null;
  let redirectDomain: string | null = null;
  let tempFailure: string | null = null;
  let permFailure: string | null = null;
  let hasInclude = false;
  const includeDomains: string[] = [];

  // Parse maxauthrate
  if (rest.match(SPF_MAX_AUTH_RATE_REGEX)) {
    maxAuthRate = parseFloat(rest.match(SPF_MAX_AUTH_RATE_REGEX)?.groups?.rate || '0');
  }

  // Parse redirectdomain
  if (rest.match(SPF_REDIRECT_DOMAIN_REGEX)) {
    redirectDomain = rest.match(SPF_REDIRECT_DOMAIN_REGEX)?.groups?.domain;
  }

  // Parse tempfail
  if (rest.match(SPF_TEMP_FAILURE_REGEX)) {
    tempFailure = rest.match(SPF_TEMP_FAILURE_REGEX)?.groups?.value;
  }

  // Parse permfail
  if (rest.match(SPF_PERM_FAILURE_REGEX)) {
    permFailure = rest.match(SPF_PERM_FAILURE_REGEX)?.groups?.value;
  }

  // Count mechanisms
  const mechanismRegexes: [RegExp, string][] = [
    [/^\s*all\s/i, 'all'],
    [/^\s*ip4:\s*(\d+\.\d+\.\d+\.\d+)/i, 'ip4'],
    [/^\s*ip6:\s*\[([0-9a-fA-F:]+)\]/i, 'ip6'],
    [/^\s*mx\s/i, 'mx'],
    [/^\s*a\s/i, 'a'],
    [/^\s*ptr\s/i, 'ptr'],
    [/^\s*include:\s*(\S+)/i, 'include'],
  ];

  for (const [regex, type] of mechanismRegexes) {
    const matches = rest.matchAll(regex);
    let count = 0;
    
    for (const match of matches) {
      if (match[1]) {
        // Extract the actual value
        let value: string;
        if (type === 'ip4') {
          value = match[1];
        } else if (type === 'ip6') {
          value = `[${match[1]}]`;
        } else if (type === 'include') {
          value = match[1].trim();
          hasInclude = true;
          includeDomains.push(value);
        } else {
          value = match[0];
        }

        // Check for nested includes
        if (type === 'include' && !value.startsWith('v=spf1')) {
          mechanisms.other++;
        } else {
          count++;
        }
      }
    }
    
    mechanisms[type as keyof MechanismCount] = count;
  }

  // Calculate auth rate (simplified - in reality this requires DNS lookups)
  const authRate = calculateAuthRate(mechanisms);

  return {
    version: match?.groups?.version || '1.0',
    hasAll,
    maxAuthRate,
    redirectDomain,
    tempFailure,
    permFailure,
    mechanisms,
    authRate,
    hasInclude,
    includeDomains,
    commonIssues: detectSPFIssues(content),
  };
}

function calculateAuthRate(mechanisms: MechanismCount): number {
  // Simplified calculation - real implementation needs DNS lookups
  const total = Object.values(mechanisms).reduce((a, b) => a + b, 0);
  
  if (total === 0) return 100;

  // Weight different mechanisms by their typical success rates
  const weights: Record<string, number> = {
    all: 95,
    ip4: 98,
    ip6: 97,
    mx: 92,
    a: 90,
    ptr: 85,
    include: 94,
    other: 80,
  };

  let weightedSum = 0;
  for (const [key, count] of Object.entries(mechanisms)) {
    if (count > 0) {
      weightedSum += weights[key as keyof typeof weights] * count;
    }
  }

  return Math.round(weightedSum / total);
}

function detectSPFIssues(content: string): SPFCommonIssue[] {
  const issues: SPFCommonIssue[] = [];

  // Check for maxauthrate (can cause delays)
  if (content.match(SPF_MAX_AUTH_RATE_REGEX)) {
    issues.push({
      type: 'MAX_AUTH_RATE',
      severity: 'MEDIUM',
      description: 'SPF uses maxauthrate which can introduce authentication delays',
      recommendation: 'Remove maxauthrate tag unless high volume requires it',
    });
  }

  // Check for redirectdomain (can cause loops)
  if (content.match(SPF_REDIRECT_DOMAIN_REGEX)) {
    issues.push({
      type: 'REDIRECT_DOMAIN',
      severity: 'MEDIUM',
      description: 'SPF uses redirectdomain which can cause authentication loops',
      recommendation: 'Remove redirectdomain and use include instead',
    });
  }

  // Check for tempfail (can cause intermittent failures)
  if (content.match(SPF_TEMP_FAILURE_REGEX)) {
    issues.push({
      type: 'TEMP_FAILURE',
      severity: 'HIGH',
      description: 'SPF uses tempfail which can cause intermittent authentication failures',
      recommendation: 'Remove tempfail and use permfail or standard mechanisms',
    });
  }

  // Check for permfail (can cause permanent failures)
  if (content.match(SPF_PERM_FAILURE_REGEX)) {
    issues.push({
      type: 'PERM_FAILURE',
      severity: 'HIGH',
      description: 'SPF uses permfail which can cause permanent authentication failures',
      recommendation: 'Remove permfail and use standard mechanisms',
    });
  }

  return issues;
}

// ============================================================================
// DKIM PARSERS & VALIDATORS
// ============================================================================

export function parseDKIM(domain: string): DKIMParsed {
  const selectors: DKIMSelectorInfo[] = [];
  
  // Common selectors to check
  const commonSelectors = ['default', 's1', 's2', 'selector1', 'selector2'];
  
  for (const selector of commonSelectors) {
    const publicKey = getDKIMPublicKey(domain, selector);
    
    if (publicKey) {
      // Parse key format
      let algorithm: string | null = null;
      let keyLength: number | null = null;

      // Try to extract algorithm and length from key header
      const headerMatch = publicKey.match(/(rsa-sha2-256|rsa-sha2-512|rsa-sha1|ed25519)/i);
      if (headerMatch) {
        algorithm = headerMatch[1].toLowerCase();
      }

      // Extract key length from base