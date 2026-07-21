import dns from 'node:dns';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export type RecordType = 'TXT' | 'MX' | 'A' | 'AAAA' | 'NS' | 'SOA';

interface DnsQueryOptions {
  /** Default timeout in milliseconds */
  defaultTimeout?: number;
  
  /** Maximum retries per query with exponential backoff */
  maxRetries?: number;
  
  /** Base delay between retries in milliseconds */
  retryBaseDelay?: number;
  
  /** Maximum total time to spend on a single record fetch */
  maxTotalTimePerRecord?: number;
}

interface DnsQueryResult<T> {
  success: boolean;
  type: RecordType | string;
  query: string;
  records: T[];
  rawResponse: Buffer | null;
  metadata: QueryMetadata;
  error?: string;
}

interface QueryMetadata {
  startTime: number;
  endTime: number;
  attempts: number;
  lastError?: Error;
}

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const DEFAULT_OPTIONS: DnsQueryOptions = {
  defaultTimeout: 5000,
  maxRetries: 3,
  retryBaseDelay: 100,
  maxTotalTimePerRecord: 20000,
};

// Common DMARC/SPF/DKIM selectors and patterns
export const DMARC_SELECTOR = '_dmarc';
export const SPF_RECORDS = ['@', '']; // @ and empty string both query the same record
export const DKIM_SELECTORS: string[] = [
  'default._domainkey',
  's1._domainkey',
  's2._domainkey',
  's3._domainkey',
  'selector1._domainkey',
  'selector2._domainkey',
];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Normalizes a domain name for DNS queries.
 * Handles trailing dots, lowercase conversion, and validation.
 */
export function normalizeDomain(domain: string): string {
  if (!domain) return '';
  
  // Remove leading/trailing whitespace
  let normalized = domain.trim();
  
  // Remove trailing dot (DNS servers handle it anyway)
  if (normalized.endsWith('.')) {
    normalized = normalized.slice(0, -1);
  }
  
  // Convert to lowercase for consistency
  return normalized.toLowerCase();
}

/**
 * Builds a fully qualified domain name by appending the base domain.
 */
export function buildFqdn(selector: string, baseDomain: string): string {
  const normalizedBase = normalizeDomain(baseDomain);
  
  if (selector.endsWith('.')) {
    // Selector already has trailing dot - just append base
    return selector + normalizedBase;
  }
  
  // Selector doesn't have trailing dot - append it with base domain
  return `${selector}.${normalizedBase}`;
}

/**
 * Creates a query string for DNS lookup.
 */
export function createQuery(type: RecordType, fqdn: string): string {
  if (fqdn.endsWith('.')) {
    return `${type} ${fqdn}`;
  }
  
  // Add trailing dot to indicate FQDN
  return `${type} ${fqdn}.`;
}

/**
 * Formats a DNS query for display.
 */
export function formatQuery(type: RecordType, fqdn: string): string {
  const normalizedFqdn = fqdn.endsWith('.') ? fqdn : `${fqdn}.`;
  return `${type.toUpperCase()} ${normalizedFqdn}`;
}

// ============================================================================
// DNS QUERY ENGINE
// ============================================================================

/**
 * Core DNS query function with retry logic and timeout handling.
 */
async function queryWithRetry<T>(
  type: RecordType,
  fqdn: string,
  options: DnsQueryOptions & { recordParser?: (data: Buffer) => T[] },
): Promise<DnsQueryResult<T>> {
  const startTime = Date.now();
  let attempts = 0;
  let lastError: Error | undefined;
  
  const maxAttempts = options.maxRetries + 1; // +1 for initial attempt
  
  while (attempts < maxAttempts) {
    attempts++;
    
    try {
      const queryStr = createQuery(type, fqdn);
      
      // Use the appropriate DNS resolver method based on record type
      let response: Buffer | null;
      
      switch (type) {
        case 'TXT':
          response = await dns.resolveTxt(fqdn, { ttl: false });
          break;
        case 'MX':
          response = await dns.resolveMx(fqdn, { ttl: false });
          break;
        case 'A':
          response = await dns.resolve4(fqdn);
          break;
        case 'AAAA':
          response = await dns.resolve6(fqdn);
          break;
        case 'NS':
          response = await dns.resolveNs(fqdn, { ttl: false });
          break;
        case 'SOA':
          response = await dns.resolveSoa(fqdn, { ttl: false });
          break;
        default:
          // Fallback to resolving TXT for unknown types
          response = await dns.resolveTxt(fqdn, { ttl: false });
      }
      
      const endTime = Date.now();
      return {
        success: true,
        type,
        query: queryStr,
        records: [],
        rawResponse: response,
        metadata: {
          startTime,
          endTime,
          attempts,
        },
      };
    } catch (error) {
      lastError = error as Error;
      
      if (attempts >= maxAttempts) {
        // Max retries exceeded - return failure
        const endTime = Date.now();
        
        return {
          success: false,
          type,
          query: createQuery(type, fqdn),
          records: [],
          rawResponse: null,
          metadata: {
            startTime,
            endTime,
            attempts,
            lastError,
          },
          error: `After ${attempts} attempts: ${(error as Error).message}`,
        };
      }
      
      // Calculate backoff delay with jitter
      const baseDelay = options.retryBaseDelay || 100;
      const exponentialDelay = Math.min(
        (baseDelay * 2 ** (attempts - 1)),
        5000, // Cap at 5 seconds
      );
      
      await new Promise(resolve => 
        setTimeout(resolve, exponentialDelay + Math.random() * 100)
      );
    }
  }
  
  return {
    success: false,
    type,
    query: createQuery(type, fqdn),
    records: [],
    rawResponse: null,
    metadata: {
      startTime,
      endTime: Date.now(),
      attempts,
      lastError,
    },
    error: 'Maximum retry limit reached',
  };
}

/**
 * Fetches a single TXT record with parsing.
 */
async function fetchTxtRecord(
  fqdn: string,
  options: DnsQueryOptions & { 
    recordParser?: (data: Buffer) => string[];
  },
): Promise<DnsQueryResult<string[]>> {
  const parser = options.recordParser || defaultTxtParser;
  
  return queryWithRetry('TXT', fqdn, {
    ...options,
    recordParser: parser,
  });
}

/**
 * Default TXT record parser - splits on whitespace.
 */
function defaultTxtParser(data: Buffer): string[] {
  if (!data || data.length === 0) return [];
  
  // Split by whitespace (spaces and tabs)
  const parts = data.toString().split(/\s+/);
  return parts;
}

/**
 * Fetches a DMARC record.
 */
export async function fetchDmarcRecord(
  domain: string,
  options: DnsQueryOptions = {},
): Promise<DnsQueryResult<string[]>> {
  const fqdn = buildFqdn(DMARC_SELECTOR, domain);
  
  return fetchTxtRecord(fqdn, { ...DEFAULT_OPTIONS, ...options });
}

/**
 * Fetches an SPF record.
 */
export async function fetchSpfRecord(
  domain: string,
  options: DnsQueryOptions = {},
): Promise<DnsQueryResult<string[]>> {
  const queries: string[] = [];
  
  // Query both @ and empty selector (both resolve to the same record)
  for (const selector of SPF_RECORDS) {
    const fqdn = buildFqdn(selector, domain);
    queries.push(fqdn);
  }
  
  // Fetch from all selectors and merge results
  const results: DnsQueryResult<string[]>[] = [];
  
  for (const fqdn of queries) {
    const result = await fetchTxtRecord(fqdn, options);
    results.push(result);
    
    if (!result.success && !results.some(r => r.success)) {
      // If all failed, return the last error
      break;
    }
  }
  
  // Merge successful records
  const merged: DnsQueryResult<string[]> = {
    success: results.some(r => r.success),
    type: 'SPF',
    query: `@.${normalizeDomain(domain)}`,
    records: [],
    rawResponse: null,
    metadata: {
      startTime: Math.min(...results.map(r => r.metadata.startTime)),
      endTime: Math.max(...results.map(r => r.metadata.endTime)),
      attempts: results.reduce((sum, r) => sum + r.metadata.attempts, 0),
    },
  };
  
  // Combine all records from successful queries
  for (const result of results) {
    if (result.success) {
      merged.records.push(...result.records);
    } else if (!merged.error && !result.error) {
      merged.error = result.error;
    }
  }
  
  return merged;
}

/**
 * Fetches all common DKIM records.
 */
export async function fetchDkimRecords(
  domain: string,
  selectors: string[] = [],
  options: DnsQueryOptions = {},
): Promise<DnsQueryResult<string[]>[]> {
  const queries: string[] = [];
  
  // Use provided selectors or defaults
  const dkimSelectors = selectors.length > 0 ? selectors : DKIM_SELECTORS;
  
  for (const selector of dkimSelectors) {
    const fqdn = buildFqdn(selector, domain);
    queries.push(fqdn);
  }
  
  // Fetch all records
  const results: DnsQueryResult<string[]>[] = [];
  
  for (const fqdn of queries) {
    const result = await fetchTxtRecord(fqdn, options);
    results.push(result);
    
    if (!result.success && !results.some(r => r.success)) {
      // If all failed, we can stop early
      break;
    }
  }
  
  return results;
}

/**
 * Fetches MX records for a domain.
 */
export async function fetchMxRecords(
  domain: string,
  options: DnsQueryOptions = {},
): Promise<DnsQueryResult<dns.MxRecord[]>> {
  const fqdn = buildFqdn('', domain); // Empty selector
  
  return queryWithRetry('MX', fqdn, { ...DEFAULT_OPTIONS, ...options });
}

/**
 * Fetches A/AAAA records for a domain.
 */
export async function fetchAddressRecords(
  domain: string,
  type: 'A' | 'AAAA' = 'A',
  options: DnsQueryOptions = {},
): Promise<DnsQueryResult<string[]>> {
  const fqdn = buildFqdn('', domain);
  
  return queryWithRetry(type, fqdn, { ...DEFAULT_OPTIONS, ...options });
}

// ============================================================================
// DMARC/SPF/DKIM PARSER UTILITIES
// ============================================================================

/**
 * Parses a DMARC TXT record into structured data.
 */
export interface DmarcRecordData {
  v: string; // Version (should be "DMARC1")
  p?: 'none' | 'quarantine' | 'reject'; // Policy
  sp?: 'none' | 'quarantine' | 'reject'; // Subdomain policy
  rua?: string[]; // Aggregate reporting URLs
  ruf?: string[]; // Failure reporting URLs
  rso?: string[]; // OSINT reporting URLs
  adkim?: 's' | 's' | undefined; // Subdomain tag (strict)
  aspf?: 's' | 's' | undefined; // Authenticated sender policy (strict)
  pct?: number; // Percentage tag
}

/**
 * Parses a DMARC record string into structured data.
 */
export function parseDmarcRecord(record: string): DmarcRecordData {
  const result: DmarcRecordData = { v: 'DMARC1' };
  
  if (!record || !record.trim()) return result;
  
  // Split by whitespace and process each tag
  const tags = record.split(/\s+/);
  
  for (const tag of tags) {
    const [key, ...valueParts] = tag.split('=');
    const value = valueParts.join('=').trim();
    
    switch (key.toLowerCase()) {
      case 'v':
        result.v = value;
        break;
        
      case 'p':
        if (['none', 'quarantine', 'reject'].includes(value)) {
          result.p = value as DmarcRecordData['p'];
        }
        break;
        
      case 'sp':
        if (['none', 'quarantine', 'reject'].includes(value)) {
          result.sp = value as DmarcRecordData['sp'];
        }
        break;
        
      case 'rua':
        // Multiple URLs can be specified, separated by semicolons
        const ruaUrls = value.split(';').map(u => u.trim()).filter(Boolean);
        result.rua = ruaUrls;
        break;
        
      case 'ruf':
        const rufUrls = value.split(';').map(u => u.trim()).filter(Boolean);
        result.ruf = rufUrls;
        break;
        
      case 'rso':
        const rsoUrls = value.split(';').map(u => u.trim()).filter(Boolean);
        result.rso = rsoUrls;
        break;
        
      case 'adkim':
        if (value === 's') {
          result.adkim = 's'; // Strict mode
        }
        break;
        
      case 'aspf':
        if (value === 's') {
          result.aspf = 's'; // Strict mode
        }
        break;
        
      case 'pct':
        const pctValue = parseInt(value, 10);
        if (!isNaN(pctValue) && pctValue >= 0 && pctValue <= 100) {
          result.pct = pctValue;
        }
        break;
    }
  }
  
  return result;
}

/**
 * Parses an SPF record string into structured data.
 */
export interface SpfRecordData {
  v: string; // Version (should be "spf1")
  p?: 'none' | 'softfail' | 'hardfail'; // Policy
  a?: string[]; // Allow IP addresses
  mx?: boolean; // Allow MX records
  include?: string[]; // Include other SPF records
  exp?: number; // Expiration time in seconds
}

/**
 * Parses an SPF record string into structured data.
 */
export function parseSpfRecord(record: string): SpfRecordData {
  const result: SpfRecordData = { v: 'spf1' };
  
  if (!record || !record.trim()) return result;
  
  // Split by whitespace and process each mechanism
  const mechanisms = record.split(/\s+/);
  
  for (const mech of mechanisms) {
    const [key, ...valueParts] = mech.split('=');
    const value = valueParts.join('=').trim();
    
    switch (key.toLowerCase()) {
      case 'v':
        result.v = value;
        break;
        
      case 'p':
        if (['none', 'softfail', 'hardfail'].includes(value)) {
          result.p = value as SpfRecordData['p'];
        }
        break;
        
      case 'a':
        // IP addresses, comma-separated