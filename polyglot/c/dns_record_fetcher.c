/*
 * polyglot/c/dns_record_fetcher.c
 * 
 * DMARC Audit DNS Record Fetcher
 * 
 * Queries DNS for MX, SPF, DKIM, and DMARC records needed to audit
 * a domain's email authentication posture. Returns structured results
 * ready for analysis and reporting.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

/* ==================== CONSTANTS ==================== */

#define DNS_PORT 53
#define DNS_TIMEOUT 2.0
#define MAX_RECORDS 128
#define MAX_TXT_SIZE 4096

/* Record type constants for quick lookup */
enum dns_type {
    T_A = 1,
    T_CNAME = 5,
    T_MX = 15,
    T_TXT = 16,
    T_SOA = 6,
    T_NS = 2,
};

/* ==================== DATA STRUCTURES ==================== */

typedef struct {
    int type;                    /* Record type (A, MX, TXT, etc) */
    char name[256];             /* Domain name */
    union {
        uint32_t a;              /* A record IP */
        uint16_t mx_priority;    /* MX priority */
        char txt[MAX_TXT_SIZE]; /* TXT content */
    } data;
} dns_record;

typedef struct {
    int id;                      /* DNS transaction ID */
    uint16_t flags;              /* Response flags (RD, RA, etc) */
    uint16_t qdcount;            /* Question count */
    uint16_t ancount;            /* Answer count */
    uint16_t nscount;            /* Authority section count */
    uint16_t arcount;            /* Additional section count */
} dns_header;

typedef struct {
    char domain[256];
    int id;
    uint16_t flags;
    uint16_t qdcount, ancount, nscount, arcount;
    dns_record records[MAX_RECORDS];
    size_t record_count;
} dns_response;

/* ==================== HELPER FUNCTIONS ==================== */

static void init_header(dns_header *h) {
    memset(h, 0, sizeof(*h));
    h->flags = 0x8040;  /* RD (recursion desired), RA (response authorized) */
}

static int encode_name(const char *name, unsigned char *buf, size_t bufsize) {
    if (!name || !buf) return -1;
    
    const unsigned char *p = (const unsigned char *)name;
    size_t len = strlen(name);
    
    /* Check for compression pointer */
    if ((len & 0xC0) == 0x80 && bufsize >= 2) {
        buf[0] = len >> 6;
        buf[1] = len & 0x3F | 0xC0;
        return 2;
    }
    
    if (len > bufsize - 1) return -1;
    buf[0] = len;
    memcpy(buf + 1, p, len);
    return len + 1;
}

static int encode_question(dns_header *h, const char *name, unsigned char *buf, size_t bufsize) {
    int offset = sizeof(*h);
    
    /* Encode name */
    int nlen = encode_name(name, buf + offset, bufsize - offset);
    if (nlen < 0 || offset + nlen >= bufsize) return -1;
    offset += nlen;
    
    /* Type and class */
    h->qdcount++;
    buf[offset++] = T_TXT;   /* Always query TXT for DMARC/SPF/DKIM */
    buf[offset++] = 0x0001;  /* IN class (network) */
    
    return offset - sizeof(*h);
}

static int decode_name(const unsigned char *p, const unsigned char *end, 
                       char *out, size_t outsize) {
    if (!p || !out || p >= end) return -1;
    
    int offset = 0;
    while (offset < 256 && offset < (int)(end - p)) {
        unsigned char len = p[offset];
        
        /* Compression pointer */
        if ((len & 0xC0) == 0x80) {
            int ptr_offset = ((len >> 2) & 3) | 
                            ((p[offset + 1] << 6) & 0xC0);
            offset += 2;
            
            /* Resolve pointer */
            const unsigned char *base = (const unsigned char *)h->id;
            int ptr_pos = ptr_offset - sizeof(*h);
            if (ptr_pos < 0 || ptr_pos >= bufsize) return -1;
            
            memcpy(out, base + ptr_pos, outsize - offset);
            return offset;
        }
        
        /* Regular label */
        if (len == 0) {
            /* Null-terminated or end of name */
            break;
        }
        
        if (offset + len > 256) return -1;
        memcpy(out + offset, p + offset, len);
        offset += len;
    }
    
    out[offset] = '\0';
    return offset;
}

/* ==================== DNS QUERY FUNCTIONS ==================== */

static int dns_query_raw(const char *domain, int type, unsigned char *buf, 
                         size_t bufsize) {
    struct sockaddr_in server;
    int sock;
    ssize_t sent, recv_len;
    
    /* Initialize resolver */
    if (res_init() < 0) return -1;
    
    /* Create UDP socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(DNS_PORT);
    
    /* Use default resolver's DNS servers */
    struct hostent *res = gethostbyname("8.8.8.8");  /* Fallback to Google */
    if (!res) {
        res = gethostbyname("1.1.1.1");               /* Cloudflare fallback */
    }
    
    memcpy(server.sin_addr.s_addr, res->h_addr_list[0], 
           res->h_length);
    
    memset(buf, 0, bufsize);
    
    /* Build query header and question */
    dns_header *hdr = (dns_header *)buf;
    init_header(hdr);
    
    int qoffset = sizeof(*hdr);
    if (encode_question(hdr, domain, buf + qoffset, bufsize - qoffset) < 0) {
        close(sock);
        return -1;
    }
    
    /* Send query */
    sent = sendto(sock, buf, bufsize, 0, 
                  (struct sockaddr *)&server, sizeof(server));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }
    
    /* Receive response with timeout */
    struct timeval tv = {.tv_sec = (long)(DNS_TIMEOUT)};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    recv_len = recv(sock, buf, bufsize - 1024, 0);
    if (recv_len < 0) {
        perror("recv");
        close(sock);
        return -1;
    }
    
    /* Check for truncated response */
    if ((hdr->flags & 0x20) && recv_len > 512) {
        fprintf(stderr, "Warning: Truncated response\n");
    }
    
    close(sock);
    return (int)recv_len;
}

/* ==================== RECORD PARSING FUNCTIONS ==================== */

static int parse_mx_record(const unsigned char *p, const unsigned char *end, 
                           dns_record *rec) {
    if (!p || !rec || p >= end) return -1;
    
    /* MX: priority (2 bytes) + name */
    rec->data.mx_priority = ((uint16_t)p[0] << 8) | p[1];
    
    int offset = 2;
    if (decode_name(p + offset, end, rec->name, sizeof(rec->name)) < 0) {
        return -1;
    }
    
    rec->type = T_MX;
    return 0;
}

static int parse_txt_record(const unsigned char *p, const unsigned char *end, 
                            dns_record *rec) {
    if (!p || !rec || p >= end) return -1;
    
    /* TXT: length (2 bytes) + data */
    uint16_t txt_len = ((uint16_t)p[0] << 8) | p[1];
    
    int offset = 2;
    if (offset + txt_len > (int)(end - p)) {
        txt_len = end - p - offset;
    }
    
    /* Handle multi-part TXT records */
    while (txt_len > 0) {
        uint16_t chunk_len = ((uint16_t)p[offset] << 8) | p[offset + 1];
        
        if (!rec->data.txt[0]) {
            rec->type = T_TXT;
            rec->data.txt[0] = '\0';
        }
        
        int copy_len = chunk_len > MAX_TXT_SIZE - strlen(rec->data.txt) 
                      ? MAX_TXT_SIZE - strlen(rec->data.txt) : chunk_len;
        
        if (copy_len > 0) {
            strncat(rec->data.txt, p + offset, copy_len);
            txt_len -= copy_len;
            offset += copy_len;
        } else {
            break;
        }
    }
    
    return 0;
}

static int parse_a_record(const unsigned char *p, const unsigned char *end, 
                          dns_record *rec) {
    if (!p || !rec || p >= end) return -1;
    
    /* A: 4 bytes IP */
    rec->data.a = ((uint32_t)p[0] << 24) | (p[1] << 16) | 
                  (p[2] << 8) | p[3];
    
    rec->type = T_A;
    return 0;
}

static int parse_cname_record(const unsigned char *p, const unsigned char *end, 
                              dns_record *rec) {
    if (!p || !rec || p >= end) return -1;
    
    /* CNAME: name */
    int offset = 0;
    if (decode_name(p + offset, end, rec->name, sizeof(rec->name)) < 0) {
        return -1;
    }
    
    rec->type = T_CNAME;
    return 0;
}

/* ==================== MAIN FETCHER FUNCTIONS ==================== */

static int fetch_mx_records(const char *domain, dns_response *resp) {
    unsigned char buf[256];
    memset(resp, 0, sizeof(*resp));
    
    if (dns_query_raw(domain, T_MX, buf, sizeof(buf)) < 0) {
        return -1;
    }
    
    const dns_header *hdr = (const dns_header *)buf;
    resp->id = hdr->id;
    resp->flags = hdr->flags;
    resp->qdcount = hdr->qdcount;
    resp->ancount = hdr->ancount;
    resp->nscount = hdr->nscount;
    resp->arcount = hdr->arcount;
    
    /* Parse MX answers */
    const unsigned char *p = buf + sizeof(*hdr);
    for (int i = 0; i < hdr->ancount && resp->record_count < MAX_RECORDS; i++) {
        int offset = 0;
        
        /* Skip name (should be same as question) */
        while ((unsigned char)*p & 0xC0 == 0x80 || *p == 0) {
            p++;
            offset++;
        }
        if (*p == 0) {
            p++;
            offset++;
        }
        
        /* Skip type and class */
        p += 4;
        offset += 4;
        
        /* Parse MX record */
        if (parse_mx_record(p, buf + sizeof(buf), &resp->records[resp->record_count]) == 0) {
            resp->record_count++;
        }
    }
    
    return 0;
}

static int fetch_txt_records(const char *domain, dns_response *resp) {
    unsigned char buf[256];
    memset(resp, 0, sizeof(*resp));
    
    if (dns_query_raw(domain, T_TXT, buf, sizeof(buf)) < 0) {
        return -1;
    }
    
    const dns_header *hdr = (const dns_header *)buf;
    resp->id = hdr->id;
    resp->flags = hdr->flags;
    resp->qdcount = hdr->qdcount;
    resp->ancount = hdr->ancount;
    resp->nscount = hdr->nscount;
    resp->arcount = hdr->arcount;
    
    /* Parse TXT answers */
    const unsigned char *p = buf + sizeof(*hdr);
    for (int i = 0; i < hdr->ancount && resp->record_count < MAX_RECORDS; i++) {
        int offset = 0;
        
        /* Skip name */
        while ((unsigned char)*p & 0xC0 == 0x80 || *p == 0) {
            p++;
            offset++;
        }
        if (*p == 0) {
            p++;
            offset++;
        }
        
        /* Skip type and class */
        p += 4;
        offset += 4;
        
        /* Parse TXT record */
        if (parse_txt_record(p, buf + sizeof(buf), &resp->records[resp->record_count]) == 0) {
            resp->record_count++;
        }
    }
    
    return 0;
}

static int fetch_a_records(const char *domain, dns_response *resp) {
    unsigned char buf[256];
    memset(resp, 0, sizeof(*resp));
    
    if (dns_query_raw(domain, T_A, buf, sizeof(buf)) < 0) {
        return -1;
    }
    
    const dns_header *hdr = (const dns_header *)buf;
    resp->id = hdr->id;
    resp->flags = hdr->flags;
    resp->qdcount = hdr->qdcount;
    resp->ancount = hdr->ancount;
    resp->nscount = hdr->nscount;
    resp->arcount = hdr->arcount;
    
    /* Parse A answers */
    const unsigned char *p = buf + sizeof(*hdr);
    for (int i = 0; i < hdr->ancount && resp->record_count < MAX_RECORDS; i++) {
        int offset = 0;
        
        /* Skip name */
        while ((unsigned char)*p & 0xC0 == 0x80 || *p == 0) {
            p++;
            offset++;
        }
        if (*p == 0) {
            p++;
            offset++;
        }
        
        /* Skip type and class */
        p += 4;
        offset += 4;
        
        /* Parse A record */
        if (parse_a_record(p, buf + sizeof(buf), &resp->records[resp->record_count]) == 0) {
            resp->record_count++;
        }
    }
    
    return 0;
}

/* ==================== UNIFIED INTERFACE ==================== */

int fetch_all_records(const char *domain, dns_response *resp) {
    if (!domain || !resp) return -1;
    
    memset(resp, 0, sizeof(*resp