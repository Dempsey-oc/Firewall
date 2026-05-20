using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net;

namespace Firewall;

/// <summary>
/// Strongly-typed configuration root for the firewall.
/// </summary>
/// <remarks>
/// Bind from the <c>"Firewall"</c> configuration section using
/// <c>services.AddFirewall().BindConfiguration("Firewall")</c>.
/// </remarks>
public sealed class FirewallOptions
{
    /// <summary>The configuration section name used by the binding extensions.</summary>
    public const string SectionName = "Firewall";

    /// <summary>Master kill-switch. When <see langword="false"/>, the middleware short-circuits to allow.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Behaviour when a provider fails (e.g. Cloudflare range fetch). Defaults to <see cref="ProviderFailurePolicy.UseLastKnownGood"/>.</summary>
    public ProviderFailurePolicy OnProviderFailure { get; set; } = ProviderFailurePolicy.UseLastKnownGood;

    /// <summary>Configuration for the response sent on deny.</summary>
    [Required]
    public BlockResponseOptions OnDeny { get; set; } = new();

    /// <summary>Configuration for trusted proxy chains used for <c>X-Forwarded-For</c> resolution.</summary>
    [Required]
    public TrustedProxyOptions TrustedProxies { get; set; } = new();

    /// <summary>How frequently providers re-fetch their range data. Default 15 minutes. Cross-validated by <c>FirewallOptionsValidator</c>.</summary>
    public TimeSpan ProviderRefreshInterval { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long a single rule evaluation may take before being abandoned. Default 250ms. Cross-validated by <c>FirewallOptionsValidator</c>.</summary>
    public TimeSpan EvaluationTimeout { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>If <see langword="true"/>, IPs are HMAC-hashed before being emitted to logs and traces.</summary>
    public bool HashIpsInTelemetry { get; set; }

    /// <summary>Declarative rule sets bound from configuration (allow/deny lists).</summary>
    [Required]
    public RuleSetOptions Rules { get; set; } = new();
}

/// <summary>Failure-handling policy for asynchronous providers.</summary>
public enum ProviderFailurePolicy
{
    /// <summary>Deny all traffic when the provider fails.</summary>
    FailClosed = 0,

    /// <summary>Allow all traffic when the provider fails. Not recommended for production.</summary>
    FailOpen = 1,

    /// <summary>Continue using the last successful snapshot. Default.</summary>
    UseLastKnownGood = 2,
}

/// <summary>Shape of the response emitted on deny.</summary>
public sealed class BlockResponseOptions
{
    /// <summary>HTTP status code to write. Default 403.</summary>
    [Range(400, 599)]
    public int StatusCode { get; set; } = 403;

    /// <summary>Optional body content. Empty by default — recommended in production to avoid information disclosure.</summary>
    public string Body { get; set; } = string.Empty;

    /// <summary>Optional <c>Content-Type</c> for the response body.</summary>
    public string ContentType { get; set; } = "text/plain; charset=utf-8";

    /// <summary>Optional retry-after header value in seconds.</summary>
    [Range(0, int.MaxValue)]
    public int? RetryAfterSeconds { get; set; }
}

/// <summary>Trusted proxy chain configuration for <c>X-Forwarded-For</c> resolution.</summary>
public sealed class TrustedProxyOptions
{
    /// <summary>Individual proxy IPs whose <c>X-Forwarded-For</c> header is honoured.</summary>
    public IList<string> KnownProxies { get; set; } = new List<string>();

    /// <summary>CIDR networks whose <c>X-Forwarded-For</c> header is honoured.</summary>
    public IList<string> KnownNetworks { get; set; } = new List<string>();

    /// <summary>Maximum number of forwarders to walk back through. Default 1.</summary>
    [Range(0, 16)]
    public int ForwardLimit { get; set; } = 1;
}

/// <summary>Declarative allow/deny rule sets bound from configuration.</summary>
public sealed class RuleSetOptions
{
    /// <summary>If <see langword="true"/>, requests are admitted only if at least one allow rule matches.</summary>
    public bool DefaultDeny { get; set; }

    /// <summary>Explicit IPs that are always allowed.</summary>
    public IList<string> AllowedIps { get; set; } = new List<string>();

    /// <summary>Explicit IPs that are always denied. Evaluated before allow rules.</summary>
    public IList<string> DeniedIps { get; set; } = new List<string>();

    /// <summary>CIDR ranges that are always allowed.</summary>
    public IList<string> AllowedCidrs { get; set; } = new List<string>();

    /// <summary>CIDR ranges that are always denied. Evaluated before allow rules.</summary>
    public IList<string> DeniedCidrs { get; set; } = new List<string>();

    /// <summary>Two-letter ISO 3166 country codes that are always allowed (requires a geo provider).</summary>
    public IList<string> AllowedCountries { get; set; } = new List<string>();

    /// <summary>Two-letter ISO 3166 country codes that are always denied (requires a geo provider).</summary>
    public IList<string> DeniedCountries { get; set; } = new List<string>();

    /// <summary>If <see langword="true"/>, traffic from the loopback adapter is always allowed.</summary>
    public bool AllowLocalhost { get; set; } = true;
}

/// <summary>A typed parsed proxy entry, populated by validation.</summary>
public sealed record TrustedProxyEntry(IPAddress? Address, string? Cidr);
