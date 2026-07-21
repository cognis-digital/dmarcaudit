#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#define MAX_LABEL 64
#define MAX_RECORD 1024
#define MAX_MX 32
#define MAX_TXT 8
#define MAX_DKIM_SELECTORS 16

/* ==================== DNS QUERY HELPERS ==================== */

typedef struct {
    char *domain;
    int port;
} DnsConfig;

static const char *g_dns_server = "8.8.8.8";
static int g_dns_port = 53;

static int dns_init(void) {
    if (res_init() < 0) {
        perror("res_init");
        return -1;
    }
    return 0;
}

static int dns_query_txt(const char *domain, const char *type, char **result, size_t *len) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    memset(&addr, 0, sizeof(addr));
    inet_pton(AF_INET, g_dns_server, &addr.sin_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_dns_port);
    
    char query[MAX_RECORD];
    size_t qlen = 0;
    
    /* Build DNS query */
    snprintf(query, sizeof(query), "%s %s IN TXT", domain, type);
    qlen = strlen(query) + 1;
    
    ssize_t nrecv = recvfrom(sock, query, sizeof(query), 0, NULL, NULL);
    close(sock);
    
    if (nrecv < 0 || nrecv <= (ssize_t)qlen) return -1;
    
    /* Parse response */
    char *resp = malloc(nrecv + 1);
    memcpy(resp, query, nrecv);
    resp[nrecv] = '\0';
    
    /* Find TXT records in response */
    char *p = resp;
    while (p < resp + nrecv) {
        if (*p == 'T' && p[1] == 'X' && p[2] == 'T') {
            /* Found TXT section, extract data */
            char *start = p + 3;
            size_t datalen = 0;
            
            while (datalen < nrecv - (p - resp)) {
                if (*p == '"') {
                    start++;
                    p++;
                    break;
                } else if (*p == ' ') {
                    break;
                } else {
                    datalen++;
                    p++;
                }
            }
            
            *result = malloc(datalen + 1);
            memcpy(*result, start, datalen);
            (*result)[datalen] = '\0';
            *len = datalen;
            free(resp);
            return 0;
        } else {
            p++;
        }
    }
    
    free(resp);
    return -1;
}

static int dns_query_spf(const char *domain, char **result) {
    return dns_query_txt(domain, "SPF", result, NULL);
}

static int dns_query_dmarc(const char *domain, char **result) {
    /* DMARC is in _dmarc subdomain */
    char dmarc_domain[MAX_LABEL + 12];
    snprintf(dmarc_domain, sizeof(dmarc_domain), "_dmarc.%s", domain);
    return dns_query_txt(dmarc_domain, "TXT", result, NULL);
}

static int dns_query_dkim_selector(const char *domain, const char *selector, 
                                   char **result) {
    /* Format: selector._domainkey.domain. TXT */
    char query[MAX_RECORD];
    snprintf(query, sizeof(query), "%s.%s._domainkey.%s", 
             selector, "TXT", domain);
    
    return dns_query_txt(query, "TXT", result, NULL);
}

/* ==================== SPF PARSER (RFC 7208) ==================== */

typedef struct {
    int valid;
    char *raw_record;
    int has_all;
    int has_include;
    int max_hosts;
    int mechanisms_count;
    char *mechanisms[MAX_RECORD];
} SpfResult;

static void spf_free(SpfResult *s) {
    if (s->raw_record) free(s->raw_record);
    for (int i = 0; i < s->mechanisms_count && s->mechanisms[i]; i++) {
        free(s->mechanisms[i]);
    }
}

static int spf_parse(const char *record, SpfResult *result) {
    memset(result, 0, sizeof(*result));
    result->raw_record = strdup(record);
    
    /* Remove leading/trailing whitespace and quotes */
    size_t len = strlen(record);
    while (len > 0 && isspace((unsigned char)record[0])) record++, len--;
    while (len > 0 && isspace((unsigned char)record[len-1])) record[--len] = '\0';
    
    if (len == 0 || !strncasecmp(record, "\"", 1)) {
        /* Quoted string - extract content */
        size_t i;
        for (i = 1; i < len && record[i] != '"'; i++);
        if (record[i] == '"') record[i] = '\0';
    }
    
    result->valid = (len > 0);
    
    /* Check for mechanisms */
    char *p = strdup(record);
    int in_quote = 0;
    size_t start = 0, end = 0;
    
    while (*p) {
        if (!in_quote && isspace((unsigned char)*p)) {
            if (start < end) {
                p[end] = '\0';
                result->mechanisms[result->mechanisms_count++] = strdup(p + start);
            }
            start = 0;
        } else {
            end++;
        }
        
        /* Handle quotes */
        if (*p == '"' && (start == 0 || p[-1] != '\\')) {
            in_quote = !in_quote;
        }
        
        p++;
    }
    
    /* Last mechanism */
    if (start < end) {
        result->mechanisms[result->mechanisms_count++] = strdup(p);
    }
    
    free(p);
    
    /* Check for specific mechanisms */
    for (int i = 0; i < result->mechanisms_count; i++) {
        const char *m = result->mechanisms[i];
        
        if (!strncasecmp(m, "all", 3)) {
            result->has_all = 1;
        } else if (!strncasecmp(m, "include:", 8) || 
                   !strncasecmp(m, "ainclude:", 9)) {
            result->has_include = 1;
        }
    }
    
    /* Count unique hosts (simplified - just count IPs/domains) */
    for (int i = 0; i < result->mechanisms_count; i++) {
        const char *m = result->mechanisms[i];
        
        /* IP ranges */
        if (strchr(m, '.') || strchr(m, ':')) {
            result->max_hosts += 1;
        } else if (!strncasecmp(m, "ip4:", 4) || !strncasecmp(m, "ip6:", 4)) {
            /* IP ranges */
            char *range = m + 4;
            while (*range && isspace((unsigned char)*range)) range++;
            if (strncmp(range, "-", 1) != 0) {
                result->max_hosts += 2; /* Start and end of range */
            }
        } else if (!strncasecmp(m, "a:", 2) || !strncasecmp(m, "a4:", 3)) {
            /* Authenticated mail sources - count as domain */
            result->max_hosts += 1;
        }
    }
    
    return result->valid ? 0 : -1;
}

/* ==================== DKIM PARSER (RFC 6376) ==================== */

typedef struct {
    int found;
    char selector[MAX_LABEL];
    char domain[MAX_RECORD];
    char *public_key;
    size_t key_len;
    int valid_format;
    int rsa2048;
    int rsa4096;
} DkimResult;

static void dkim_free(DkimResult *d) {
    if (d->public_key) free(d->public_key);
}

static int dkim_parse(const char *selector, const char *domain, 
                      const char *record, DkimResult *result) {
    memset(result, 0, sizeof(*result));
    
    strncpy(result->selector, selector, MAX_LABEL - 1);
    result->selector[MAX_LABEL - 1] = '\0';
    
    /* Extract domain from query (remove selector._domainkey.) */
    const char *q = record;
    while (*q && isspace((unsigned char)*q)) q++;
    if (*q == '"') q++;
    result->domain[MAX_RECORD - 1] = '\0';
    
    /* Parse key parameters */
    int in_key = 0, brace_depth = 0;
    size_t key_start = 0, key_end = 0;
    
    for (size_t i = 0; q[i]; i++) {
        if (!in_key) {
            if (*q == 'k' && q[1] == ':' && !strncasecmp(q + 2, "rsa", 3)) {
                /* RSA key */
                while (isspace((unsigned char)q[i+1])) i++;
                
                if (!strncasecmp(q + i, "2048", 4)) {
                    result->rsa2048 = 1;
                } else if (!strncasecmp(q + i, "4096", 4)) {
                    result->rsa4096 = 1;
                }
                
                /* Find key data */
                while (q[i] && isspace((unsigned char)q[i])) i++;
                if (*q == '"') q++, i++;
            } else if (*q == 'b' && q[1] == ':' && !strncasecmp(q + 2, "rsa", 3)) {
                /* B64 encoded key */
                while (isspace((unsigned char)q[i+1])) i++;
                
                if (!strncasecmp(q + i, "2048", 4)) {
                    result->rsa2048 = 1;
                } else if (!strncasecmp(q + i, "4096", 4)) {
                    result->rsa4096 = 1;
                }
                
                /* Extract b64 key */
                while (q[i] && isspace((unsigned char)q[i])) i++;
                if (*q == '"') q++, i++;
            } else if (*q == 'v' && q[1] == ':' && !strncasecmp(q + 2, "rsa", 3)) {
                /* Version */
                while (isspace((unsigned char)q[i+1])) i++;
                
                if (!strncasecmp(q + i, "1", 1)) {
                    result->valid_format = 1;
                } else if (!strncasecmp(q + i, "rsa2048", 7) || 
                           !strncasecmp(q + i, "rsa4096", 7)) {
                    result->valid_format = 1;
                }
            }
        } else {
            if (*q == '"') {
                key_start = i + 1;
                in_key = 0;
            } else if (isspace((unsigned char)*q) || *q == ',') {
                if (key_start < key_end) {
                    result->public_key = malloc(key_end - key_start + 1);
                    memcpy(result->public_key, q + key_start, key_end - key_start);
                    result->public_key[key_end - key_start] = '\0';
                    result->key_len = key_end - key_start;
                }
                in_key = 0;
            } else if (*q == ',') {
                /* End of parameter */
                break;
            }
        }
        
        if (in_key) {
            brace_depth++;
        } else if (*q == '"') {
            key_end = i + 1;
            in_key = 1;
        }
        
        q++;
    }
    
    /* Check for trailing quote */
    while (isspace((unsigned char)*q)) q++;
    if (*q == '"') q++, *q = '\0';
    
    result->found = 1;
    return result->valid_format ? 0 : -1;
}

/* ==================== DMARC PARSER (RFC 7505/7506) ==================== */

typedef struct {
    int valid;
    char *raw_record;
    char policy[32];      /* p=tag */
    char rua[MAX_RECORD]; /* Reporting */
    char ruf[MAX_RECORD]; /* Failure reporting */
    char sp_policy[32];   /* subdomain policy */
    int pct;              /* Percentage */
    int has_spf_fail;     /* spf=fail */
    int has_dkim_fail;    /* dkim=fail */
    int has_adkim_fail;   /* adkim=s/strict */
    int has_aspf_fail;    /* aspf=s/strict */
} DmarcResult;

static void dmarc_free(DmarcResult *d) {
    if (d->raw_record) free(d->raw_record);
}

static int dmarc_parse(const char *record, DmarcResult *result) {
    memset(result, 0, sizeof(*result));
    
    /* Remove quotes and whitespace */
    size_t len = strlen(record);
    while (len > 0 && isspace((unsigned char)record[0])) record++, len--;
    while (len > 0 && isspace((unsigned char)record[len-1])) record[--len] = '\0';
    
    if (len == 0 || !strncasecmp(record, "\"", 1)) {
        size_t i;
        for (i = 1; i < len && record[i] != '"'; i++);
        if (record[i] == '"') record[i] = '\0';
    }
    
    result->valid = (len > 0);
    result->raw_record = strdup(record);
    
    /* Parse DMARC tags */
    char *p = strdup(record);
    int in_value = 0, value_start = 0;
    
    while (*p) {
        if (!in_value && isspace((unsigned char)*p)) {
            if (value_start < p - record) {
                size_t vlen = p - record - value_start;
                const char *v = record + value_start;
                
                /* Check for policy tags */
                if (!strncasecmp(v, "p=", 2)) {
                    strncpy(result->policy, v + 2, sizeof(result->policy) - 1);
                    result->policy[sizeof(result->policy) - 1] = '\0';
                } else if (!strncasecmp(v, "sp=", 3)) {
                    strncpy(result->sp_policy, v + 3, sizeof(result->sp_policy) - 1);
                    result->sp_policy[sizeof(result->sp_policy) - 1] = '\0';
                } else if (!strncasecmp(v, "pct=", 4)) {
                    char *end;
                    result->pct = (int)strtol(v + 4, &end, 10);
                } else if (!strncasecmp(v, "spf=fail", 8)) {
                    result->has_spf_fail = 1;
                } else if (!strncasecmp(v, "dkim=fail", 9)) {
                    result->has_dkim_fail = 1;
                } else if (!strncasecmp(v, "adkim=s", 7) || !strncasecmp(v, "adkim=strict", 12)) {
                    result->has_adkim_fail = 1;
                } else if (!strncasecmp(v, "aspf=s", 7) || !strncasecmp(v, "aspf=strict", 12)) {
                    result->has_aspf_fail = 1;
                } else if (!strncasecmp(v, "rua=", 4)) {
                    strncpy(result->rua, v + 4, sizeof(result->rua) - 1);
                    result->rua[sizeof(result->rua) - 1] = '\0';
                } else if (!strncasecmp(v, "ruf=", 4