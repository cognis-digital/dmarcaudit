use std::fmt;
use std::str::FromStr;

/// Policy types for DMARC enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// No action taken (default)
    None,
    /// Put suspicious mail in quarantine
    Quarantine,
    /// Reject suspicious mail
    Reject,
}

impl fmt::Display for DmarcPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarcPolicy::None => write!(f, "none"),
            DmarcPolicy::Quarantine => write!(f, "quarantine"),
            DmarcPolicy::Reject => write!(f, "reject"),
        }
    }
}

impl FromStr for DmarcPolicy {
    type Err = ParseDmarcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim().to_lowercase();
        match trimmed.as_str() {
            "none" => Ok(DmarcPolicy::None),
            "quarantine" | "q" => Ok(DmarcPolicy::Quarantine),
            "reject" | "r" => Ok(DmarcPolicy::Reject),
            "" => Err(ParseDmarcError::EmptyPolicy),
            _ => Err(ParseDmarcError::UnknownPolicy(trimmed)),
        }
    }
}

/// SPF checking mode (ASPF)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AspfMode {
    /// Relaxed: Check if SPF passes, but don't require it
    Relaxed,
    /// Strict: Require SPF to pass
    Strict,
}

impl fmt::Display for AspfMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AspfMode::Relaxed => write!(f, "r"),
            AspfMode::Strict => write!(f, "s"),
        }
    }
}

impl FromStr for AspfMode {
    type Err = ParseDmarcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim().to_lowercase();
        match trimmed.as_str() {
            "relaxed" | "r" => Ok(AspfMode::Relaxed),
            "strict" | "s" => Ok(AspfMode::Strict),
            "" => Err(ParseDmarcError::EmptyMode),
            _ => Err(ParseDmarcError::UnknownMode(trimmed)),
        }
    }
}

/// Domain matching mode (ADKIM)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdkimMode {
    /// Relaxed: Match domain loosely
    Relaxed,
    /// Strict: Exact match required
    Strict,
}

impl fmt::Display for AdkimMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdkimMode::Relaxed => write!(f, "r"),
            AdkimMode::Strict => write!(f, "s"),
        }
    }
}

impl FromStr for AdkimMode {
    type Err = ParseDmarcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim().to_lowercase();
        match trimmed.as_str() {
            "relaxed" | "r" => Ok(AdkimMode::Relaxed),
            "strict" | "s" => Ok(AdkimMode::Strict),
            "" => Err(ParseDmarcError::EmptyMode),
            _ => Err(ParseDmarcError::UnknownMode(trimmed)),
        }
    }
}

/// Parsing errors for DMARC records
#[derive(Debug, Clone)]
pub enum ParseDmarcError {
    EmptyPolicy,
    UnknownPolicy(String),
    EmptyMode,
    UnknownMode(String),
    InvalidPercentage(u16),
    MalformedRecord(String),
}

impl fmt::Display for ParseDmarcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPolicy => write!(f, "Empty policy value"),
            Self::UnknownPolicy(s) => write!(f, "Unknown policy: {}", s),
            Self::EmptyMode => write!(f, "Empty mode value"),
            Self::UnknownMode(s) => write!(f, "Unknown mode: {}", s),
            Self::InvalidPercentage(p) => write!(f, "Invalid percentage: {}", p),
            Self::MalformedRecord(s) => write!(f, "Malformed record: {}", s),
        }
    }
}

impl std::error::Error for ParseDmarcError {}

/// A parsed DMARC record from a TXT value
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    /// The version string (should be "DMARC1")
    pub version: String,
    /// The enforcement policy
    pub policy: DmarcPolicy,
    /// Aggregate report addresses
    pub rua: Vec<String>,
    /// Forensic report addresses (optional)
    pub ruf: Option<Vec<String>>,
    /// Subdomain policy (optional)
    pub sp: Option<DmarcPolicy>,
    /// ADKIM mode
    pub adkim: AdkimMode,
    /// ASPF mode
    pub aspf: AspfMode,
    /// Percentage enforcement (0-100)
    pub pct: u16,
    /// Raw TXT value for debugging
    pub raw: String,
}

impl DmarcRecord {
    /// Parse a DMARC record from a raw TXT string
    /// 
    /// Handles multiple records by returning the first valid one found.
    pub fn parse(txt_value: &str) -> Result<Self, ParseDmarcError> {
        let parts: Vec<&str> = txt_value.split(';').collect();
        
        if parts.is_empty() || parts[0].trim().is_empty() {
            return Err(ParseDmarcError::MalformedRecord(txt_value.to_string()));
        }

        // Parse version (first part)
        let first_part = parts[0].trim();
        let mut version = "DMARC1".to_string();
        
        if !first_part.starts_with("v=") {
            return Err(ParseDmarcError::MalformedRecord(txt_value.to_string()));
        }

        let ver_str = &first_part[2..];
        version = ver_str.trim().to_string();

        // Parse remaining parts
        let mut policy = DmarcPolicy::None;
        let mut rua = Vec::new();
        let mut ruf = None;
        let mut sp = None;
        let mut adkim = AdkimMode::Relaxed;
        let mut aspf = AspfMode::Relaxed;
        let mut pct: u16 = 100;

        for part in &parts[1..] {
            let trimmed = part.trim();
            
            // Skip empty parts
            if trimmed.is_empty() {
                continue;
            }

            // Parse policy (p=)
            if let Some(policy_part) = trimmed.strip_prefix("p=") {
                policy = policy_part.parse()?;
                continue;
            }

            // Parse subdomain policy (sp=)
            if let Some(sp_part) = trimmed.strip_prefix("sp=") {
                sp = Some(sp_part.parse()?);
                continue;
            }

            // Parse aggregate reports (rua=)
            if let Some(rua_part) = trimmed.strip_prefix("rua=") {
                rua.push(rua_part.to_string());
                continue;
            }

            // Parse forensic reports (ruf=)
            if let Some(ruf_part) = trimmed.strip_prefix("ruf=") {
                ruf = Some(vec![ruf_part.to_string()]);
                continue;
            }

            // Parse ADKIM mode (adkim=)
            if let Some(adkim_part) = trimmed.strip_prefix("adkim=") {
                adkim = adkim_part.parse()?;
                continue;
            }

            // Parse ASPF mode (aspf=)
            if let Some(aspf_part) = trimmed.strip_prefix("aspf=") {
                aspf = aspf_part.parse()?;
                continue;
            }

            // Parse percentage (pct=)
            if let Some(pct_part) = trimmed.strip_prefix("pct=") {
                pct = pct_part.parse().map_err(|_| {
                    ParseDmarcError::InvalidPercentage(0)
                })?;
                continue;
            }

            // Unknown parameter - warn but continue
            eprintln!("Warning: unknown DMARC parameter in record: {}", trimmed);
        }

        Ok(DmarcRecord {
            version,
            policy,
            rua,
            ruf,
            sp,
            adkim,
            aspf,
            pct,
            raw: txt_value.to_string(),
        })
    }

    /// Check if this is a valid DMARC1 record
    pub fn is_valid(&self) -> bool {
        self.version == "DMARC1" && !self.rua.is_empty()
    }

    /// Get the effective policy (considering pct=0 disables enforcement)
    pub fn effective_policy(&self) -> DmarcPolicy {
        if self.pct == 0 {
            return DmarcPolicy::None;
        }
        self.policy
    }

    /// Check if reports are configured for aggregate reporting
    pub fn has_aggregate_reports(&self) -> bool {
        !self.rua.is_empty()
    }

    /// Check if forensic reports are configured
    pub fn has_forensic_reports(&self) -> bool {
        self.ruf.as_ref().map_or(false, |v| !v.is_empty())
    }
}

/// SPF record parser and validator
#[derive(Debug, Clone)]
pub struct SpfRecord {
    /// The raw TXT value
    pub raw: String,
    /// Parsed mechanism results
    pub mechanisms: Vec<SpfMechanism>,
    /// Whether SPF is syntactically valid
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
pub enum SpfMechanism {
    /// IP address (IPv4 or IPv6)
    Ip(std::net::IpAddr),
    /// Domain lookup
    Domain(String),
    /// Include another SPF record
    Include(String),
    /// Redirect to another domain
    Redirect(String),
    /// All mail from anywhere (catch-all)
    All,
}

impl SpfRecord {
    pub fn parse(txt_value: &str) -> Self {
        let mechanisms = txt_value.split_whitespace()
            .map(|m| {
                let trimmed = m.trim();
                
                // Handle IP addresses
                if let Ok(ip) = std::net::IpAddr::from_str(trimmed) {
                    return SpfMechanism::Ip(ip);
                }

                // Handle include statements
                if let Some(include_part) = trimmed.strip_prefix("include:") {
                    return SpfMechanism::Include(include_part.to_string());
                }

                // Handle redirect statements
                if let Some(redirect_part) = trimmed.strip_prefix("redirect:") {
                    return SpfMechanism::Redirect(redirect_part.to_string());
                }

                // Handle all
                if trimmed.eq_ignore_ascii_case("-all") || 
                   trimmed.eq_ignore_ascii_case("~all") ||
                   trimmed.eq_ignore_ascii_case("?all") ||
                   trimmed.eq_ignore_ascii_case("+all") {
                    return SpfMechanism::All;
                }

                // Default: treat as domain lookup
                SpfMechanism::Domain(trimmed.to_string())
            })
            .collect();

        // Basic validation - must have at least one mechanism and an all statement
        let has_all = mechanisms.iter().any(|m| matches!(m, SpfMechanism::All));
        
        Self {
            raw: txt_value.to_string(),
            mechanisms,
            is_valid: !mechanisms.is_empty() && has_all,
        }
    }

    pub fn has_strict_policy(&self) -> bool {
        self.mechanisms.last().map_or(false, |m| matches!(m, SpfMechanism::All))
    }

    pub fn is_catch_all(&self) -> bool {
        self.mechanisms.iter()
            .any(|m| matches!(m, SpfMechanism::All))
    }

    pub fn get_include_domains(&self) -> Vec<&str> {
        self.mechanisms.iter()
            .filter_map(|m| match m {
                SpfMechanism::Include(d) => Some(*d),
                _ => None,
            })
            .collect()
    }
}

/// DKIM record parser and validator
#[derive(Debug, Clone)]
pub struct DkimRecord {
    /// The raw TXT value
    pub raw: String,
    /// Extracted domain from selector
    pub domain: Option<String>,
    /// Whether this appears to be a valid DKIM public key
    pub is_valid: bool,
}

impl DkimRecord {
    pub fn parse(txt_value: &str) -> Self {
        let trimmed = txt_value.trim();
        
        // Basic validation - should start with v=DKIM1
        let starts_with_header = trimmed.starts_with("v=DKIM1");
        
        // Try to extract domain from selector
        let domain = if let Some(selector_part) = trimmed.strip_prefix("k=rsa") {
            // Format: k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ...
            // Domain is typically in the header or can be inferred
            if let Some(header_part) = selector_part.strip_prefix("h=") {
                // Header format: h=rsa-sha256; tag=f; s=email.example.com; ...
                if let Some(domain_part) = header_part.strip_prefix("s=") {
                    domain_part.trim().to_string()
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        // Basic validity check
        let has_public_key = trimmed.contains("p=") && 
                           (trimmed.len() > 50 || trimmed.contains("MIG"));

        Self {
            raw: txt_value.to_string(),
            domain: if domain != "unknown" { Some(domain) } else { None },
            is_valid: starts_with_header && has_public_key,
        }
    }

    pub fn get_selector(&self) -> Option<&str> {
        self.raw.split_whitespace()
            .find(|s| s.starts_with("k="))
            .and_then(|s| s.strip_prefix("k="))
    }

    pub fn is_rsa_key(&self) -> bool {
        self.raw.contains("k=rsa")
    }

    pub fn is_ecdsa_key(&self) -> bool {
        self.raw.contains("k=ecdsa-p256") || 
        self.raw.contains("k=ecdsa-p384") ||
        self.raw.contains("k=ecdsa-p521")
    }
}

/// Main audit result with prioritized fixes
#[derive(Debug, Clone)]
pub struct DmarcAuditResult {
    /// The domain being audited
    pub domain: String,
    /// Parsed DMARC record (if found)
    pub dmarc_record: Option<DmarcRecord>,
    /// SPF record analysis
    pub spf_analysis: SpfAnalysis,
    /// DKIM record analysis  
    pub dkim_analysis: DkimAnalysis,
    /// Overall spoofability