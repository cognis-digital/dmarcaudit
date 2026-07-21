using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Dns;
using System.Text;
using System.Threading.Tasks;

namespace dmarcaudit;

/// <summary>
/// Core DNS record fetcher for DMARC/SPF/DKIM auditing.
/// </summary>
public static class DnsRecordFetcher
{
    private const int DefaultTimeoutMs = 5000;
    private const int MaxRetries = 2;

    /// <summary>
    /// Fetches all relevant DNS records for DMARC/SPF/DKIM auditing.
    /// </summary>
    public static async Task<DmarcAuditResult> AuditAsync(string domain, CancellationToken ct = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            // Parallel fetch all relevant records
            var (dmarcRecords, spfRecords, dkimRecords, mxRecords) = await FetchAllRecordsAsync(
                domain, ct);

            return new DmarcAuditResult
            {
                Domain = domain,
                DmarcRecords = dmarcRecords,
                SpfRecords = spfRecords,
                DkimRecords = dkimRecords,
                MxRecords = mxRecords,
                TotalTimeMs = stopwatch.ElapsedMilliseconds,
                Status = BuildStatus(dmarcRecords, spfRecords, dkimRecords)
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new DmarcAuditResult
            {
                Domain = domain,
                TotalTimeMs = stopwatch.ElapsedMilliseconds,
                Status = AuditStatus.Canceled
            };
        }
        catch (DnsException ex)
        {
            return new DmarcAuditResult
            {
                Domain = domain,
                Error = $"DNS lookup failed: {ex.Message}",
                TotalTimeMs = stopwatch.ElapsedMilliseconds,
                Status = AuditStatus.Error
            };
        }
    }

    private static async Task<(List<string> dmarc, List<string> spf, List<string> dkim, List<MxRecord> mx)> 
        FetchAllRecordsAsync(string domain, CancellationToken ct)
    {
        var timeoutCt = CancellationTokenSource.CreateLinkedTokenSource(ct).Token;

        // DMARC: _dmarc.domain.com
        var dmarcTask = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(100, timeoutCt);
                return await Dns.QueryAsync(domain, "_dmarc", DnsRecordType.Txt)
                    .Select(r => r.ToString())
                    .ToListAsync(timeoutCt);
            }
            catch (OperationCanceledException) when (timeoutCt.IsCancellationRequested)
            {
                return new List<string>();
            }
        });

        // SPF: @ or domain.com in TXT records
        var spfTask = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(100, timeoutCt);
                var allTxt = await Dns.QueryAsync(domain, DnsRecordType.Txt)
                    .Select(r => r.ToString())
                    .ToListAsync(timeoutCt);

                return allTxt.Where(s => s.StartsWith("v=spf1")).ToList();
            }
            catch (OperationCanceledException) when (timeoutCt.IsCancellationRequested)
            {
                return new List<string>();
            }
        });

        // DKIM: Look for common selectors in TXT records
        var dkimTask = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(100, timeoutCt);
                var allTxt = await Dns.QueryAsync(domain, DnsRecordType.Txt)
                    .Select(r => r.ToString())
                    .ToListAsync(timeoutCt);

                // Common DKIM selectors to check
                var commonSelectors = new[] { "default", "s1", "s2", "s3", "mail", "selector1" };
                
                var dkimRecords = new List<string>();
                foreach (var selector in commonSelectors)
                {
                    var queryName = $"{selector}._domainkey.{domain}";
                    try
                    {
                        var records = await Dns.QueryAsync(queryName, DnsRecordType.Txt);
                        if (records.Any())
                        {
                            dkimRecords.Add($"{queryName}: {string.Join(", ", records.Select(r => r.ToString()))}");
                        }
                    }
                    catch
                    {
                        // Ignore missing selectors
                    }
                }

                return dkimRecords;
            }
            catch (OperationCanceledException) when (timeoutCt.IsCancellationRequested)
            {
                return new List<string>();
            }
        });

        // MX records for completeness
        var mxTask = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(100, timeoutCt);
                return (await Dns.QueryAsync(domain, DnsRecordType.Mx))
                    .Select(r => new MxRecord
                    {
                        Exchange = r.Exchange.ToString(),
                        Priority = r.Preference
                    })
                    .OrderBy(x => x.Priority)
                    .ToList();
            }
            catch (OperationCanceledException) when (timeoutCt.IsCancellationRequested)
            {
                return new List<MxRecord>();
            }
        });

        // Wait for all tasks with timeout
        var results = await Task.WhenAll(dmarcTask, spfTask, dkimTask, mxTask);

        return (results[0], results[1], results[2], results[3]);
    }

    private static AuditStatus BuildStatus(List<string> dmarc, List<string> spf, List<string> dkim)
    {
        // Check DMARC
        var hasDmarc = dmarc.Any();
        var dmarcPolicy = dmarc.FirstOrDefault()?.Split(' ').FirstOrDefault(s => s.StartsWith("p="))?.Substring(2);

        // Check SPF
        var hasSpf = spf.Count > 0;
        var spfValid = spf.Any(s => !string.IsNullOrEmpty(s) && s.Contains("v=spf1"));

        // Check DKIM
        var hasDkim = dkim.Count > 0;

        if (hasDmarc && dmarcPolicy == "reject" || dmarcPolicy == "quarantine")
            return AuditStatus.Good;
        
        if (!hasSpf)
            return AuditStatus.Warning; // SPF missing
        
        if (!hasDkim)
            return AuditStatus.Warning; // DKIM missing

        return AuditStatus.Good;
    }
}

/// <summary>
/// Result of a DMARC audit.
/// </summary>
public class DmarcAuditResult
{
    public string Domain { get; set; } = string.Empty;
    public List<string> DmarcRecords { get; set; } = new();
    public List<string> SpfRecords { get; set; } = new();
    public List<string> DkimRecords { get; set; } = new();
    public List<MxRecord> MxRecords { get; set; } = new();
    public int TotalTimeMs { get; set; }
    public string Error { get; set; } = string.Empty;
    public AuditStatus Status { get; set; }

    public override string ToString() => 
        $"{Domain} - {Status}: {TotalTimeMs}ms";
}

/// <summary>
/// Priority levels for audit findings.
/// </summary>
public enum AuditPriority
{
    Critical,  // DMARC not configured or set to none
    High,      // SPF missing or invalid
    Medium,    // DKIM missing
    Low        // Minor issues
}

/// <summary>
/// Status of the audit.
/// </summary>
public enum AuditStatus
{
    Good,      // All records present and valid
    Warning,   // Some records missing or weak
    Error,     // DNS lookup failed
    Canceled   // Operation was canceled
}

/// <summary>
/// MX record wrapper for easier access.
/// </summary>
public class MxRecord
{
    public int Priority { get; set; }
    public string Exchange { get; set; } = string.Empty;
}

/// <summary>
/// Provides prioritized fix recommendations based on audit results.
/// </summary>
public static class FixRecommendations
{
    public static List<FixItem> GetPrioritizedFixes(DmarcAuditResult result)
    {
        var fixes = new List<FixItem>();

        // DMARC checks
        if (!result.DmarcRecords.Any())
        {
            fixes.Add(new FixItem
            {
                Priority = AuditPriority.Critical,
                Category = "DMARC",
                Title = "Configure DMARC Policy",
                Description = "Add a DMARC TXT record at _dmarc.{domain} with p=quarantine or p=reject.",
                Example = $"_dmarc.example.com. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com\"",
                Impact = "Without DMARC, attackers can freely spoof your domain in email."
            });
        }
        else if (result.DmarcRecords.Any(r => r.Contains("p=none")))
        {
            fixes.Add(new FixItem
            {
                Priority = AuditPriority.Critical,
                Category = "DMARC",
                Title = "Strengthen DMARC Policy",
                Description = "Change p=none to at least p=quarantine.",
                Example = $"_dmarc.example.com. IN TXT \"v=DMARC1; p=quarantine\"",
                Impact = "p=none only monitors, allowing spoofed emails through."
            });
        }

        // SPF checks
        if (!result.SpfRecords.Any())
        {
            fixes.Add(new FixItem
            {
                Priority = AuditPriority.High,
                Category = "SPF",
                Title = "Configure SPF Record",
                Description = "Add an SPF TXT record at the domain apex.",
                Example = $"example.com. IN TXT \"v=spf1 mx a include:_spf.example.com -all\"",
                Impact = "Without SPF, receiving servers may reject or mark as spam."
            });
        }
        else if (result.SpfRecords.Any(r => r.Contains("-all")))
        {
            // Good, already has strict policy
        }
        else
        {
            fixes.Add(new FixItem
            {
                Priority = AuditPriority.High,
                Category = "SPF",
                Title = "Add Strict SPF Policy",
                Description = "Ensure SPF ends with -all for strict validation.",
                Example = $"example.com. IN TXT \"v=spf1 mx a include:_spf.example.com -all\"",
                Impact = "Soft fail (~~all) allows some spoofing."
            });
        }

        // DKIM checks
        if (!result.DkimRecords.Any())
        {
            fixes.Add(new FixItem
            {
                Priority = AuditPriority.Medium,
                Category = "DKIM",
                Title = "Configure DKIM Signing",
                Description = "Work with your mail provider to set up DKIM signing.",
                Example = $"selector1._domainkey.example.com. IN TXT \"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...\"",
                Impact = "Without DKIM, emails may fail DMARC checks even with good SPF/DMARC."
            });
        }

        // MX check (less critical but worth noting)
        if (!result.MxRecords.Any())
        {
            fixes.Add(new FixItem
            {
                Priority = AuditPriority.Low,
                Category = "MX",
                Title = "Verify MX Records",
                Description = "Ensure at least one MX record exists.",
                Impact = "Without MX records, email delivery may fail."
            });
        }

        return fixes;
    }
}

/// <summary>
/// A single fix recommendation.
/// </summary>
public class FixItem
{
    public AuditPriority Priority { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Example { get; set; } = string.Empty;
    public string Impact { get; set; } = string.Empty;

    public override string ToString() => 
        $"{Priority} - [{Category}] {Title}: {Description}";
}

/// <summary>
/// Generates a human-readable report.
/// </summary>
public static class ReportGenerator
{
    public static string GenerateReport(DmarcAuditResult result, List<FixItem> fixes)
    {
        var sb = new StringBuilder();

        sb.AppendLine($"DMARC Audit Report: {result.Domain}");
        sb.AppendLine(new string('-', 50));
        sb.AppendLine($"Status: {result.Status} | Time: {result.TotalTimeMs}ms");
        sb.AppendLine(new string('-', 50));

        if (!string.IsNullOrEmpty(result.Error))
        {
            sb.AppendLine($"Error: {result.Error}");
            return sb.ToString();
        }

        // Summary
        sb.AppendLine("\n--- Summary ---\n");

        var hasDmarc = result.DmarcRecords.Any();
        var hasSpf = result.SpfRecords.Any();
        var hasDkim = result.DkimRecords.Any();

        sb.AppendLine($"DMARC:    {(hasDmarc ? "✓ Present" : "✗ Missing")}");
        sb.AppendLine($"SPF:      {(hasSpf ? "✓ Present" : "✗ Missing")}");
        sb.AppendLine($"DKIM:     {(hasDkim ? "✓ Present" : "✗ Missing")}");

        // Detailed findings
        sb.AppendLine("\n--- DMARC Details ---\n");
        if (hasDmarc)
        {
            foreach (var record in result.DmarcRecords)
            {
                sb.AppendLine($"  {record}");
            }
        }
        else
        {
            sb.AppendLine("  No DMARC records found.");
        }

        // SPF details
        sb.AppendLine("\n--- SPF Details ---\n");
        if (hasSpf)
        {
            foreach (var record in result.SpfRecords)
            {
                sb.AppendLine($"  {record}");
            }
        }
        else
        {
            sb.AppendLine("  No SPF records found.");
        }

        // DKIM details
        sb.AppendLine("\n--- DKIM Details ---\n");
        if (hasDkim)
        {
            foreach (var record in result.DkimRecords)
            {
                sb.AppendLine($"  {record}");
            }
        }
        else
        {
            sb.AppendLine("  No DKIM records found.");
        }

        // MX details
        sb.AppendLine("\n--- MX Records ---\n");
        if (result.MxRecords.Any())
        {
            foreach (var mx in result.MxRecords)
            {
                sb.AppendLine($"  Priority: {mx.Priority} | Exchange: {mx.Exchange}");
            }
        }
        else
        {
            sb.AppendLine("  No MX records found.");
        }

        // Prioritized fixes
        if (fixes.Count > 0)
        {
            sb.AppendLine("\n--- Prioritized Fixes ---\n");
            
            foreach (var fix in fixes.OrderBy(f => f.Priority))
            {
                sb.AppendLine($"[{fix.Priority}] {fix.Title}");
                sb.AppendLine($"   Category: {fix.Category}");
                sb.AppendLine($"   Description: {fix.Description}");
                
                if (!string.IsNullOrEmpty(fix.Example))
                {
                    sb.AppendLine($"   Example: {fix.Example}");
                }

                sb.AppendLine($"   Impact: {fix.Impact}\n");
            }
        }

        return sb.ToString();
    }
}

/// <summary>
/// Console application entry point with demo.
/// </summary>
public class Program
{
    public static void Main(string[] args)
    {
        // Default domain to audit (change via args or env var)
        string domain = args.Length