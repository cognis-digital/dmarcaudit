#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <cstdint>
#include <array>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <regex>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>

namespace dmarcaudit {

// DNS constants and types
constexpr uint16_t QTYPE_TXT = 16;
constexpr uint16_t QTYPE_MX = 15;
constexpr int32_t DEFAULT_PORT = 53;
constexpr size_t MAX_RECORDS = 100;
constexpr size_t MAX_LABEL_LEN = 64;

// DNS header structure (RFC 1035)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    static constexpr size_t SIZE = 12;

    bool is_response() const { return (flags & 0x8000) != 0; }
    bool has_authoritative_answer() const { return (flags & 0x0400) != 0; }
    uint16_t rcode() const { return flags & 0xF; }
};

// DNS Question structure
struct DnsQuestion {
    char qname[MAX_LABEL_LEN + 1];
    uint16_t qtype;
    uint16_t qclass;

    static constexpr size_t SIZE = 18;
};

// DNS Answer structure (generic)
struct DnsAnswer {
    char rdata[256]; // Sufficient for most TXT records
    uint16_t ttl;
    uint16_t type;
    std::string name;

    static constexpr size_t SIZE = 270;
};

// DMARC result structure
struct DmarcResult {
    bool found = false;
    std::string policy;
    std::string rua;
    std::string ruf;
    std::string adkim;
    std::string aspf;
    uint16_t p = 0; // 0=none, 1=quarantine, 2=reject

    void parse(const std::string& txt) {
        if (!txt.empty() && txt.find("v=DMARC1") == 0) {
            found = true;
            
            // Extract policy
            auto p_match = regex_search(txt, std::regex(R"(p=(none|quarantine|reject))"));
            if (p_match.first != std::string::npos) {
                policy = p_match.second.str();
                
                if (policy == "p=none") p = 0;
                else if (policy == "p=quarantine") p = 1;
                else if (policy == "p=reject") p = 2;
            }

            // Extract reporting addresses
            auto rua_match = regex_search(txt, std::regex(R"(rua=([^;]+))"));
            if (rua_match.first != std::string::npos) {
                rua = rua_match.second.str();
            }

            auto ruf_match = regex_search(txt, std::regex(R"(ruf=([^;]+))"));
            if (ruf_match.first != std::string::npos) {
                ruf = ruf_match.second.str();
            }

            // Extract alignment modes
            auto adkim_match = regex_search(txt, std::regex(R"(adkim=(none|simplified|relaxed|strict))"));
            if (adkim_match.first != std::string::npos) {
                adkim = adkim_match.second.str();
            }

            auto aspf_match = regex_search(txt, std::regex(R"(aspf=(none|simplified|relaxed|strict))"));
            if (aspf_match.first != std::string::npos) {
                aspf = aspf_match.second.str();
            }
        }
    }

    int get_policy_strength() const {
        switch (p) {
            case 0: return 1;   // none - weakest
            case 1: return 2;   // quarantine
            case 2: return 3;   // reject - strongest
            default: return 1;
        }
    }

    std::string get_policy_string() const {
        switch (p) {
            case 0: return "none";
            case 1: return "quarantine";
            case 2: return "reject";
            default: return "unknown";
        }
    }
};

// SPF result structure
struct SpfResult {
    bool found = false;
    std::string policy;
    uint16_t p = 0; // 0=none, 1=softfail, 2=hardfail

    void parse(const std::string& txt) {
        if (!txt.empty() && txt.find("v=spf1") == 0) {
            found = true;

            auto p_match = regex_search(txt, std::regex(R"(p=(all|softall|softfail|hardfail))"));
            if (p_match.first != std::string::npos) {
                policy = p_match.second.str();

                if (policy == "p=all") p = 2;
                else if (policy == "p=softall" || policy == "p=softfail") p = 1;
            }
        }
    }

    int get_policy_strength() const {
        switch (p) {
            case 0: return 1;   // none - weakest
            case 1: return 2;   // softfail
            case 2: return 3;   // hardfail - strongest
            default: return 1;
        }
    }

    std::string get_policy_string() const {
        switch (p) {
            case 0: return "none";
            case 1: return "softfail";
            case 2: return "hardfail";
            default: return "unknown";
        }
    }
};

// DKIM result structure
struct DkimResult {
    bool found = false;
    std::string selector;
    std::string domain;
    uint16_t p = 0; // 0=none, 1=softfail, 2=hardfail

    void parse(const std::string& txt) {
        if (!txt.empty() && txt.find("v=DKIM1") == 0) {
            found = true;

            auto p_match = regex_search(txt, std::regex(R"(p=(all|softall|softfail|hardfail))"));
            if (p_match.first != std::string::npos) {
                policy = p_match.second.str();

                if (policy == "p=all") p = 2;
                else if (policy == "p=softall" || policy == "p=softfail") p = 1;
            }
        }
    }

    int get_policy_strength() const {
        switch (p) {
            case 0: return 1;   // none - weakest
            case 1: return 2;   // softfail
            case 2: return 3;   // hardfail - strongest
            default: return 1;
        }
    }

    std::string get_policy_string() const {
        switch (p) {
            case 0: return "none";
            case 1: return "softfail";
            case 2: return "hardfail";
            default: return "unknown";
        }
    }
};

// Main DMARC audit result
struct DmarcAuditResult {
    std::string domain;
    DmarcResult dmarc;
    SpfResult spf;
    DkimResult dkim;
    
    // Additional DNS records found
    std::vector<std::pair<std::string, std::string>> mx_records;
    std::vector<std::string> txt_records;

    // Spoofability score (0-100, higher = more spoofable)
    int spoofability_score = 0;
    
    // Prioritized fixes
    std::vector<FixPriority> prioritized_fixes;

    enum class FixPriority {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    };

    struct FixPriority {
        FixPriority priority;
        std::string fix;
        int estimated_effort; // 1-5 days
    };

    void calculate_spoofability() {
        spoofability_score = 0;

        // DMARC contribution (max 30 points)
        if (!dmarc.found) {
            spoofability_score += 30;
            prioritized_fixes.push_back({FixPriority::CRITICAL, 
                "Add DMARC record with p=reject policy", 7});
        } else if (dmarc.p == 0) {
            spoofability_score += 25;
            prioritized_fixes.push_back({FixPriority::HIGH,
                "Change DMARC policy from none to quarantine or reject", 3});
        } else if (dmarc.p == 1) {
            spoofability_score += 10;
            prioritized_fixes.push_back({FixPriority::MEDIUM,
                "Consider upgrading DMARC policy from quarantine to reject", 2});
        }

        // SPF contribution (max 25 points)
        if (!spf.found) {
            spoofability_score += 25;
            prioritized_fixes.push_back({FixPriority::CRITICAL,
                "Add SPF record with v=spf1 and p=hardfail", 2});
        } else if (spf.p == 0) {
            spoofability_score += 15;
            prioritized_fixes.push_back({FixPriority::HIGH,
                "Change SPF policy from none to hardfail", 1});
        }

        // DKIM contribution (max 25 points)
        if (!dkim.found) {
            spoofability_score += 25;
            prioritized_fixes.push_back({FixPriority::CRITICAL,
                "Configure DKIM signing for all outgoing mail", 14});
        } else if (dkim.p == 0) {
            spoofability_score += 15;
            prioritized_fixes.push_back({FixPriority::HIGH,
                "Change DKIM policy from none to hardfail", 3});
        }

        // MX records check (max 10 points)
        if (mx_records.empty()) {
            spoofability_score += 10;
            prioritized_fixes.push_back({FixPriority::LOW,
                "Verify MX records point to legitimate mail servers", 1});
        } else if (mx_records.size() > 2) {
            spoofability_score += 5;
            prioritized_fixes.push_back({FixPriority::LOW,
                "Reduce number of MX records for easier verification", 0.5});
        }

        // Cap at 100
        if (spoofability_score > 100) {
            spoofability_score = 100;
        }
    }

    std::string get_status_string() const {
        switch (spoofability_score / 25) {
            case 0: return "Well protected";
            case 1: return "Moderately protected";
            case 2: return "Vulnerable";
            case 3: return "Highly vulnerable";
            default: return "Unknown state";
        }
    }

    std::string get_summary() const {
        std::ostringstream oss;
        
        oss << domain << "\n";
        oss << "Spoofability Score: " << spoofability_score << "/100\n";
        oss << "Status: " << get_status_string() << "\n\n";

        // DMARC section
        oss << "--- DMARC ---\n";
        if (dmarc.found) {
            oss << "  Found: Yes\n";
            oss << "  Policy: " << dmarc.get_policy_string() << "\n";
            oss << "  Reporting (rua): " << (dmarc.rua.empty() ? "Not configured" : dmarc.rua) << "\n";
            oss << "  Alignment: adkim=" << dmarc.adkim << ", aspf=" << dmarc.aspf << "\n\n";
        } else {
            oss << "  Found: No\n\n";
        }

        // SPF section
        oss << "--- SPF ---\n";
        if (spf.found) {
            oss << "  Found: Yes\n";
            oss << "  Policy: " << spf.get_policy_string() << "\n\n";
        } else {
            oss << "  Found: No\n\n";
        }

        // DKIM section
        oss << "--- DKIM ---\n";
        if (dkim.found) {
            oss << "  Found: Yes\n";
            oss << "  Selector: " << dkim.selector << "\n";
            oss << "  Policy: " << dkim.get_policy_string() << "\n\n";
        } else {
            oss << "  Found: No\n\n";
        }

        // MX records section
        if (!mx_records.empty()) {
            oss << "--- MX Records ---\n";
            for (const auto& [name, value] : mx_records) {
                oss << "  " << name << ": " << value << "\n";
            }
            oss << "\n";
        }

        // Prioritized fixes
        oss << "--- Prioritized Fixes ---\n\n";
        
        int priority_count = 0;
        for (const auto& fix : prioritized_fixes) {
            if (priority_count++ >= 5) break; // Limit output
            
            std::string prefix;
            switch (fix.priority) {
                case FixPriority::CRITICAL: prefix = "[CRITICAL] "; break;
                case FixPriority::HIGH: prefix = "[HIGH] "; break;
                case FixPriority::MEDIUM: prefix = "[MEDIUM] "; break;
                default: prefix = "[LOW] "; break;
            }

            oss << "  " << prefix << fix.fix << "\n";
            oss << "    Estimated effort: " << fix.estimated_effort << " days\n\n";
        }

        return oss.str();
    }
};

// DNS Record Fetcher class
class DnsRecordFetcher {
private:
    int socket_fd;
    struct sockaddr_in server_addr;
    
public:
    DnsRecordFetcher(const std::string& domain, uint16_t port = DEFAULT_PORT) 
        : socket_fd(-1), server_addr{} {
        
        // Initialize DNS header flags
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        // Try multiple DNS servers for redundancy
        const std::vector<std::string> dns_servers = {
            "8.8.8.8",      // Google
            "1.1.1.1",      // Cloudflare
            "208.67.222.222" // OpenDNS
        };

        for (const auto& ip : dns_servers) {
            if (resolve_and_connect(ip)) {
                break;
            }
        }
    }

    ~DnsRecordFetcher() {
        close(socket_fd);
    }

    bool resolve_and_connect(const std::string& ip) {
        struct hostent* he = gethostbyname(ip.c_str());
        if (!he) return false;

        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, he->h_addr_list[0], 
               sizeof(server_addr.sin_addr));
        server_addr.sin_port = htons(DEFAULT_PORT);

        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) return false;

        // Set timeout for faster failover
        struct timeval tv = {1, 0}; // 1 second timeout
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        return true;
    }

    std::string build_query(const std::string& qname, uint16_t qtype) {
        std::ostringstream oss;

        // DNS Header (12