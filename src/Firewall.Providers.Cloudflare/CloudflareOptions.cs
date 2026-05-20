using System;
using System.ComponentModel.DataAnnotations;

namespace Firewall.Providers.Cloudflare;

/// <summary>Configuration for the Cloudflare IP range provider.</summary>
public sealed class CloudflareOptions
{
    /// <summary>The configuration section name. Defaults to <c>"Firewall:Cloudflare"</c>.</summary>
    public const string SectionName = "Firewall:Cloudflare";

    /// <summary>The URL returning Cloudflare's IPv4 ranges (one per line).</summary>
    [Url]
    public string IPv4Url { get; set; } = "https://www.cloudflare.com/ips-v4";

    /// <summary>The URL returning Cloudflare's IPv6 ranges (one per line).</summary>
    [Url]
    public string IPv6Url { get; set; } = "https://www.cloudflare.com/ips-v6";

    /// <summary>Refresh cadence for the background service.</summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(6);

    /// <summary>If <see langword="true"/>, the host startup blocks until the first successful refresh.</summary>
    public bool BlockOnStartup { get; set; }
}
