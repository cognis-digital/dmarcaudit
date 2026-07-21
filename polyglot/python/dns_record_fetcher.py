"""
polyglot/python/dns_record_fetcher.py

A robust DNS record fetcher for DMARC/SPF/DKIM auditing.
Fetches records from multiple sources with fallback strategies and retry logic.
"""

import socket
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any


@dataclass
class DNSResponse:
    """Structured response from a single DNS query."""
    name: str
    record_type: str
    ttl: int
    records: List[str] = field(default_factory=list)
    status_code: int = 0
    error: Optional[str] = None


@dataclass
class ServerConfig:
    """Configuration for a DNS server."""
    address: Tuple[str, int]
    priority: int = 1
    timeout: float = 5.0
    
    def __init__(self, host: str, port: int = 53, priority: int = 1, timeout: float = 5.0):
        self.address = (host, port)
        self.priority = priority
        self.timeout = timeout


class DNSFetcher:
    """
    Multi-source DNS record fetcher with retry and fallback logic.
    
    Strategy:
    1. Try primary nameservers from the domain's NS records
    2. Fall back to public resolvers (8.8.8.8, 1.1.1.1)
    3. Use local resolver as last resort
    
    All queries use UDP first, TCP fallback for large responses.
    """
    
    DEFAULT_SERVERS: List[ServerConfig] = [
        ServerConfig("8.8.8.8", priority=2),
        ServerConfig("1.1.1.1", priority=3),
        ServerConfig("9.9.9.9", priority=4),
        ServerConfig("208.67.222.222", priority=5),
    ]
    
    def __init__(
        self,
        servers: Optional[List[ServerConfig]] = None,
        base_timeout: float = 10.0,
        max_retries: int = 3,
        retry_delay: float = 0.25,
    ):
        self.servers = servers or self.DEFAULT_SERVERS.copy()
        self.base_timeout = base_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
    
    def _query_single(
        self, 
        server: ServerConfig, 
        name: str, 
        qtype: int,
        query_size: int = 512
    ) -> DNSResponse:
        """Query a single nameserver with TCP/UDP fallback."""
        try:
            # Build query packet
            header = self._build_header(name, qtype)
            
            # Try UDP first
            for size in [query_size, 4096]:
                response = self._udp_query(server.address, name, qtype, header, size)
                if response and response.status_code == 2:
                    return response
            
            # TCP fallback for large responses
            tcp_response = self._tcp_query(server.address, name, qtype, header, query_size)
            if tcp_response:
                return tcp_response
                
        except socket.timeout:
            pass
        except socket.gaierror as e:
            error_msg = f"DNS lookup failed: {e}"
        except socket.error as e:
            error_msg = f"Socket error: {e}"
        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {e}"
        
        return DNSResponse(
            name=name,
            record_type=self._qtype_to_str(qtype),
            ttl=0,
            records=[],
            status_code=-1,
            error=error_msg,
        )
    
    def _udp_query(
        self, 
        address: Tuple[str, int], 
        name: str, 
        qtype: int,
        header: bytes,
        size: int = 512
    ) -> Optional[bytes]:
        """Perform UDP query with connection reuse."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.base_timeout)
        
        try:
            sock.sendto(header, address)
            
            # Receive response (may need multiple packets for large answers)
            data = b""
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    break
                data += chunk
            
            return data
            
        finally:
            sock.close()
    
    def _tcp_query(
        self, 
        address: Tuple[str, int], 
        name: str, 
        qtype: int,
        header: bytes,
        size: int = 4096
    ) -> Optional[bytes]:
        """Perform TCP query for large responses."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.base_timeout)
        
        try:
            sock.connect(address)
            
            # Send header
            sock.sendall(header)
            
            # Receive response with size prefix (TCP mode)
            data = b""
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    break
                data += chunk
            
            return data
            
        finally:
            sock.close()
    
    def _build_header(self, name: str, qtype: int) -> bytes:
        """Build DNS query header and question section."""
        # Header: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
        flags = 0x0100  # Standard query, recursion desired
        
        # Question section
        qname = self._encode_name(name)
        question = qname + bytes([qtype, 1])  # QTYPE, QCLASS (IN=1)
        
        return header(2, flags, 1, 0, 0, 0) + question
    
    def _header(self, id_: int, flags: int, qdcount: int, ancount: int, nscount: int, arcount: int) -> bytes:
        """Build DNS response header."""
        return (id_ << 15 | flags).to_bytes(2, 'big') + \
               (qdcount & 0xFFFF).to_bytes(2, 'big') + \
               (ancount & 0xFFFF).to_bytes(2, 'big') + \
               (nscount & 0xFFFF).to_bytes(2, 'big') + \
               (arcount & 0xFFFF).to_bytes(2, 'big')
    
    def _encode_name(self, name: str) -> bytes:
        """Encode domain name in DNS wire format."""
        parts = name.rstrip('.').split('.')
        result = b""
        for part in parts:
            if not part:
                continue
            encoded = part.encode('idna')
            result += len(encoded).to_bytes(1, 'big') + encoded
        
        # Trailing null byte required by DNS spec
        result += b'\x00'
        return result
    
    def _qtype_to_str(self, qtype: int) -> str:
        """Convert QTYPE integer to string."""
        types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'MX', 15: 'TXT',
            28: 'AAAA', 33: 'SRV', 47: 'CAA', 257: 'SPF', 258: 'DMARC'
        }
        return types.get(qtype, f'TXT({qtype})')
    
    def _parse_response(self, data: bytes) -> DNSResponse:
        """Parse DNS response into structured format."""
        if len(data) < 12:
            return DNSResponse(
                name="", record_type="TXT", ttl=0, records=[],
                status_code=-1, error="Truncated response"
            )
        
        # Parse header
        id_ = int.from_bytes(data[0:2], 'big') & 0xFFFF
        flags = int.from_bytes(data[2:4], 'big')
        qdcount = int.from_bytes(data[4:6], 'big') & 0xFFFF
        
        rcode = (flags >> 11) & 0x0F
        status_code = 2 if rcode == 0 else -1 + rcode
        
        # Parse question section to get query name and type
        offset = 12
        qname, offset = self._parse_name(data, offset)
        qtype = int.from_bytes(data[offset:offset+2], 'big')
        
        record_type = self._qtype_to_str(qtype)
        
        # Parse answer/authority sections for TXT records
        txt_records: List[str] = []
        
        # Check answers first
        ancount = (flags >> 9) & 0x3F
        if ancount > 0 and offset < len(data):
            txt_records.extend(self._parse_answers(data, offset))
        
        # Check authority section for SPF/DMARC fallbacks
        nscount = (flags >> 10) & 0x3F
        if nscount > 0:
            txt_records.extend(self._parse_authorities(data, offset + ancount * 10))
        
        return DNSResponse(
            name=qname.decode('utf-8', errors='replace'),
            record_type=record_type,
            ttl=data[offset] if ancount and offset < len(data) else 3600,
            records=txt_records,
            status_code=status_code,
        )
    
    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parse a DNS name from wire format. Returns (name, new_offset)."""
        if offset >= len(data):
            return "", offset
        
        length = data[offset]
        if not length:
            # Compression pointer or end of names
            if offset + 1 < len(data) and (data[offset+1] & 0xC0) == 0xC0:
                # Compression pointer - follow it
                base = ((data[offset+1] & 0x3F) << 8) | data[offset-2]
                return "", offset + 2
            else:
                return "", offset + 1
        
        if length > len(data) - offset:
            # Truncated name (common with large TXT records)
            truncated = data[offset:offset+length].rstrip(b'\x00')
            return truncated.decode('utf-8', errors='replace'), offset + length + 1
        
        start = offset + 1
        while start < len(data):
            if not data[start]:
                break
            part_len = data[start]
            if start + 1 + part_len > len(data):
                truncated = data[offset:start+1].rstrip(b'\x00')
                return truncated.decode('utf-8', errors='replace'), offset + 1 + part_len
            part = data[start+1:start+1+part_len]
            if not part:
                break
            start += 1 + part_len
        
        name = b''.join(data[offset+1:start]).rstrip(b'\x00').decode('utf-8', errors='replace')
        return name, offset + 1 + (start - offset)
    
    def _parse_answers(self, data: bytes, offset: int) -> List[str]:
        """Parse TXT records from answer section."""
        txt_records = []
        
        while offset < len(data):
            # Check for compression pointer
            if offset + 1 < len(data) and (data[offset] & 0xC0) == 0xC0:
                base = ((data[offset+1] & 0x3F) << 8) | data[offset-2]
                txt_records.extend(self._parse_txt_at_offset(data, base))
            else:
                # Regular record
                name_len = data[offset]
                
                if offset + 1 + name_len > len(data):
                    break
                
                name_end = offset + 1 + name_len
                name = data[offset+1:name_end].rstrip(b'\x00').decode('utf-8', errors='replace')
                
                # Get TTL (4 bytes)
                if name_end + 4 > len(data):
                    break
                
                ttl = int.from_bytes(data[name_end:name_end+4], 'big')
                offset += 5
                
                # Get RDATA length (2 bytes for TXT)
                if offset + 2 > len(data):
                    break
                
                rdata_len = int.from_bytes(data[offset:offset+2], 'big')
                offset += 3
                
                # Read TXT data (may span multiple records)
                while offset < len(data) and rdata_len > 0:
                    if offset + 1 > len(data):
                        break
                    
                    chunk_len = data[offset]
                    
                    if offset + 1 + chunk_len > len(data):
                        # Truncated - take what we have
                        remaining = len(data) - offset - 1
                        txt_records.append(remaining.to_bytes(2, 'big'))
                        rdata_len -= remaining
                        break
                    
                    chunk_data = data[offset+1:offset+1+chunk_len]
                    
                    if not chunk_data or (len(chunk_data) == 1 and chunk_data[0] == 0):
                        # Empty record - skip
                        offset += 2
                        continue
                    
                    txt_records.append(chunk_data.rstrip(b'\x00'))
                    rdata_len -= chunk_len
                    offset += 1 + chunk_len
        
        return [b''.join(r).decode('utf-8', errors='replace') for r in txt_records]
    
    def _parse_txt_at_offset(self, data: bytes, offset: int) -> List[str]:
        """Parse TXT records starting at a compression pointer."""
        txt_records = []
        
        while offset < len(data):
            if offset + 1 > len(data):
                break
            
            chunk_len = data[offset]
            
            if offset + 1 + chunk_len > len(data):
                remaining = len(data) - offset - 1
                txt_records.append(remaining.to_bytes(2, 'big'))
                break
            
            chunk_data = data[offset+1:offset+1+chunk_len]
            
            if not chunk_data or (len(chunk_data) == 1 and chunk_data[0] == 0):
                offset += 2
                continue
            
            txt_records.append(chunk_data.rstrip(b'\x00'))
            offset += 1 + chunk_len
        
        return [b''.join(r).decode('utf-8', errors='replace') for r in txt_records]
    
    def _parse_authorities(self, data: bytes, offset: int) -> List[str]:
        """Parse TXT records from authority section."""
        txt_records = []
        
        while offset < len(data):
            # Check for compression pointer
            if offset + 1 < len(data) and (data[offset] & 0xC0) == 0xC0:
                base = ((data[offset+1] & 0x3F) << 8) | data[offset-2]
                txt_records.extend(self._parse_txt_at_offset(data, base))
            else:
                # Regular record
                name_len = data[offset]
                
                if offset + 1 + name_len > len(data):
                    break
                
                name_end = offset + 1 + name_len
                name = data[offset+1:name_end].rstrip(b'\x00').decode('utf-8', errors='replace')
                
                # Get TTL (4 bytes)
                if name_end + 4 > len(data):
                    break
                
                ttl = int.from_bytes(data[name_end:name_end+4], 'big')
                offset += 5
                
                # Get RDATA length (2 bytes for TXT)
                if offset + 2 > len(data):
                    break
                
                rdata_len = int.from_bytes(data[offset:offset+2], 'big')
                offset += 3
                
                # Read TXT data
                while offset < len(data) and rdata_len > 0:
                    if offset + 1 > len(data):
                        break
                    
                    chunk_len = data[offset]
                    
                    if offset + 1 + chunk_len > len(data):
                        remaining = len(data) - offset - 1
                        txt_records.append(remaining.to_bytes(2, 'big'))
                        rdata_len -= remaining
                        break
                    
                    chunk_data = data[offset+1:offset+1+chunk_len]
                    
                    if not chunk_data or (len(chunk_data) == 1 and chunk_data[0] == 0):
                        offset += 2
                        continue
                    
                    txt_records.append(chunk_data.rstrip(b'\x00'))
                    rdata_len -= chunk_len
                    offset += 1 + chunk_len
        
        return [b''.join(r