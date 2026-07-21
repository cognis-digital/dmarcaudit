use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

/// Error types for DNS operations.
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS query failed: {0}")]
    QueryFailed(String),
    
    #[error("Timeout waiting for response from {0}")]
    Timeout(SocketAddr),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("Socket error: {0}")]
    Socket(#[from] tokio::net::UdpError),
}

/// Configuration for DNS resolver behavior.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// List of DNS servers to query (for redundancy).
    pub dns_servers: Vec<SocketAddr>,
    
    /// Maximum retries per server before failing.
    pub max_retries: u32,
    
    /// Time to wait between retries.
    pub retry_delay: Duration,
    
    /// Total timeout for all queries combined.
    pub total_timeout: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            dns_servers: vec![
                "8.8.8.8:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
                "208.67.222.222:53".parse().unwrap(),
            ],
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            total_timeout: Duration::from_secs(30),
        }
    }
}

/// A single DNS response from one server.
#[derive(Debug)]
pub struct DnsResponse {
    pub server: SocketAddr,
    pub records: Vec<DnsRecord>,
    pub query_time_ms: u64,
    pub truncated: bool,
}

impl Default for DnsResponse {
    fn default() -> Self {
        Self {
            server: "0.0.0.0".parse().unwrap(),
            records: Vec::new(),
            query_time_ms: 0,
            truncated: false,
        }
    }
}

/// A parsed DNS record with metadata.
#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: RecordType,
    pub ttl: u32,
    pub data: String,
    pub source_server: SocketAddr,
}

impl Default for DnsRecord {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            rtype: RecordType::Unknown,
            ttl: 3600,
            data: String::new(),
            source_server: "0.0.0.0".parse().unwrap(),
        }
    }
}

/// DNS record types we care about for DMARC/SPF/DKIM.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    MX,
    TXT,
    A,
    AAAA,
    CNAME,
    NS,
    SRV,
    Unknown,
}

impl Default for RecordType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Result of a DNS query attempt.
#[derive(Debug)]
pub struct QueryResult {
    pub success: bool,
    pub response: Option<DnsResponse>,
    pub error: Option<DnsError>,
    pub attempts: u32,
}

impl Default for QueryResult {
    fn default() -> Self {
        Self {
            success: false,
            response: None,
            error: None,
            attempts: 0,
        }
    }
}

/// The main DNS fetcher implementation.
pub struct DnsFetcher {
    config: DnsConfig,
    socket_pool: HashMap<SocketAddr, UdpSocket>,
}

impl Default for DnsFetcher {
    fn default() -> Self {
        let mut fetcher = Self::new(DnsConfig::default());
        // Pre-create sockets for all configured servers
        for server in &fetcher.config.dns_servers {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap_or_else(|_| {
                UdpSocket::from_std(std::net::UdpStream::connect(*server).unwrap().into())
            });
            fetcher.socket_pool.insert(*server, socket);
        }
        fetcher
    }
}

impl DnsFetcher {
    /// Create a new DNS fetcher with custom configuration.
    pub fn new(config: DnsConfig) -> Self {
        let mut fetcher = Self {
            config,
            socket_pool: HashMap::new(),
        };
        
        // Initialize sockets for each server
        for server in &config.dns_servers {
            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0") {
                fetcher.socket_pool.insert(*server, socket);
            } else {
                // Fallback to connecting directly
                if let Ok(stream) = std::net::UdpStream::connect(*server) {
                    fetcher.socket_pool.insert(*server, UdpSocket::from_std(stream));
                }
            }
        }
        
        fetcher
    }

    /// Fetch a single record type for a domain.
    pub async fn fetch_record(
        &self,
        domain: &str,
        rtype: RecordType,
    ) -> QueryResult {
        let mut result = QueryResult::default();
        let query_name = format!("_{rtype:?}.{domain}");
        
        // Try each server in order
        for (attempt, server) in self.config.dns_servers.iter().enumerate() {
            if attempt >= self.config.max_retries as usize {
                break;
            }
            
            let socket = match self.socket_pool.get(server) {
                Some(sock) => sock.clone(),
                None => {
                    // Create a new socket for this server
                    if let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0") {
                        self.socket_pool.insert(*server, sock);
                        sock
                    } else {
                        continue;
                    }
                }
            };

            // Build DNS query packet (simplified for TXT/MX)
            let mut packet = [0u8; 512];
            
            // Header: Transaction ID + Flags
            packet[0..4].copy_from_slice(&[0, 0, 0, 1]); // Standard query
            
            // Question section (simplified - just length)
            let qname_len = query_name.len();
            packet[4] = (qname_len / 256) as u8;
            packet[5] = (qname_len % 256) as u8;
            
            // Question type and class
            match rtype {
                RecordType::TXT => {
                    packet[6] = 16; // TXT record type
                    packet[7] = 1;  // IN class (Internet)
                }
                RecordType::MX => {
                    packet[6] = 15; // MX record type
                    packet[7] = 1;
                }
                _ => {
                    packet[6] = 16; // Default to TXT
                    packet[7] = 1;
                }
            }

            let offset = 8;
            
            // Send the query
            let send_start = tokio::time::Instant::now();
            match socket.send_to(&packet[offset..], *server).await {
                Ok(sent) => {
                    if sent > 0 {
                        result.attempts += 1;
                        
                        // Set up timeout for this attempt
                        let total_elapsed = send_start.elapsed();
                        let remaining = self.config.total_timeout.saturating_sub(total_elapsed);
                        
                        tokio::select! {
                            recv = socket.recv_from(&mut packet[offset..]) => {
                                match recv {
                                    Ok((len, addr)) => {
                                        result.success = true;
                                        result.response = Some(DnsResponse {
                                            server: *addr,
                                            records: self.parse_response(
                                                &packet[offset..offset + len],
                                                query_name.clone(),
                                                rtype,
                                            ),
                                            query_time_ms: send_start.elapsed().as_millis() as u64,
                                            truncated: packet[0] & 0x20 != 0,
                                        });
                                    }
                                    Err(e) => {
                                        result.error = Some(DnsError::QueryFailed(format!("recv error: {}", e)));
                                    }
                                }
                            }
                            _ = tokio::time::sleep(remaining) => {
                                result.error = Some(DnsError::Timeout(*server));
                            }
                        }
                    } else {
                        result.error = Some(DnsError::QueryFailed("empty response".to_string()));
                    }
                }
                Err(e) => {
                    if attempt < self.config.max_retries as usize - 1 {
                        tokio::time::sleep(self.config.retry_delay).await;
                        continue;
                    } else {
                        result.error = Some(DnsError::QueryFailed(format!("send error: {}", e)));
                    }
                }
            }
        }

        result
    }

    /// Parse the raw DNS response into records.
    fn parse_response(&self, data: &[u8], query_name: String, rtype: RecordType) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        
        if data.len() < 12 {
            return records;
        }

        // Skip header (12 bytes) and question section
        let offset = 12;
        
        // Parse answer section
        while offset + 4 <= data.len() && data[offset] != 0 {
            if offset >= data.len() - 5 {
                break;
            }

            // Read name length
            let mut name_offset = offset;
            let mut name_len = (data[name_offset] as usize) << 8 | (data[name_offset + 1] as usize);
            
            if name_offset + 2 > data.len() {
                break;
            }

            // Read name components
            let mut name_parts: Vec<String> = Vec::new();
            let mut current_offset = offset + 2;
            
            while current_offset < data.len() && !data[current_offset] == 0 {
                if current_offset >= data.len() - 1 {
                    break;
                }
                
                let part_len = (data[current_offset] as usize) << 8 | (data[current_offset + 1] as usize);
                if current_offset + 2 + part_len > data.len() {
                    break;
                }
                
                name_parts.push(String::from_utf8_lossy(&data[current_offset + 2..current_offset + 2 + part_len]).to_string());
                current_offset += 2 + part_len;
            }

            let full_name = if !name_parts.is_empty() {
                format!("{}.{}", name_parts.join("."), query_name)
            } else {
                query_name.clone()
            };

            offset = current_offset;

            // Read type and class (skip for now, we already know rtype)
            let _rtype_u16 = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let _class_u16 = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            // Read TTL (skip, use default)
            let _ttl = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            offset += 4;

            // Read record length
            if offset >= data.len() {
                break;
            }
            
            let rlen = (data[offset] as usize) << 8 | (data[offset + 1] as usize);
            offset += 2;

            // Extract the actual record data
            let record_data = if offset + rlen <= data.len() {
                String::from_utf8_lossy(&data[offset..offset + rlen]).to_string()
            } else {
                String::from_utf8_lossy(&data[offset..]).to_string()
            };

            // Only include records that match our expected type or are interesting
            if matches!(rtype, RecordType::TXT) || 
               record_data.starts_with("v=DMARC1") ||
               record_data.starts_with("v=spf1") {
                records.push(DnsRecord {
                    name: full_name,
                    rtype: rtype.clone(),
                    ttl: 3600, // Default TTL
                    data: record_data.trim().to_string(),
                    source_server: "0.0.0.0".parse().unwrap(),
                });
            }

            offset += rlen;
        }

        records
    }

    /// Fetch all relevant DMARC/SPF/DKIM records for a domain.
    pub async fn fetch_all_records(&self, domain: &str) -> HashMap<RecordType, QueryResult> {
        let mut results = HashMap::new();

        // MX record (always check first - critical for mail routing)
        results.insert(RecordType::MX, self.fetch_record(domain, RecordType::MX).await);

        // TXT records for DMARC and SPF
        results.insert(RecordType::TXT, self.fetch_record(domain, RecordType::TXT).await);

        // DKIM selectors (common ones)
        let dkim_selectors = ["default", "s1", "s2"];
        for selector in &dkim_selectors {
            let selector_domain = format!("{}._domainkey.{}", selector, domain);
            results.insert(RecordType::TXT, self.fetch_record(&selector_domain, RecordType::TXT).await);
        }

        // A record (basic connectivity check)
        results.insert(RecordType::A, self.fetch_record(domain, RecordType::A).await);

        results
    }

    /// Fetch records with a total timeout.
    pub async fn fetch_all_with_timeout(&self, domain: &str, timeout: Duration) -> HashMap<RecordType, QueryResult> {
        let mut results = HashMap::new();
        let start = tokio::time::Instant::now();

        // Spawn concurrent queries
        let mut handles = JoinSet::new();
        
        // MX + TXT (most important)
        handles.spawn(self.fetch_record(domain, RecordType::MX));
        handles.spawn(self.fetch_record(domain, RecordType::TXT));
        
        // DKIM selectors
        for selector in &["default", "s1"] {
            let sel_domain = format!("{}._domainkey.{}", selector, domain);
            handles.spawn(self.fetch_record(&sel_domain, RecordType::TXT));
        }

        while let Some(res) = handles.join_next().await {
            if start.elapsed() < timeout {
                match res {
                    Ok((rtype, result)) => results.insert(rtype, result),
                    Err(e) => eprintln!("Query error: {}", e),
                }
            } else {
                break;
            }
        }

        // Fill in any missing with defaults
        for rtype in &[RecordType::MX, RecordType::TXT] {
            if !results.contains_key(rtype) {
                results.insert(*rtype, QueryResult {
                    success: false,
                    response: None,
                    error: Some(DnsError::Timeout(timeout)),
                    attempts: 0,
                });
            }
        }

        results
    }

    /// Get the effective DNS servers being used.
    pub fn dns_servers(&self) -> &[SocketAddr] {
        &self.config.dns_servers
    }

    /// Set custom DNS servers.
    pub fn set_dns_servers(&mut self, servers: Vec<SocketAddr>) {
        self.config.dns_servers = servers;
        
        // Re-initialize sockets
        self.socket_pool.clear();
        for server in &self.config.dns_servers {
            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0") {
                self.socket_pool.insert(*server, socket);
            }
        }
    }

    /// Get the current configuration.
    pub fn config