using System.Collections.Generic;
using System.Linq;
using System.Net;
using Firewall.Internal;
using Firewall.Networking;
using Firewall.Providers;
using Firewall.Rules;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Firewall.Configuration;

internal static partial class BinderLog
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Information,
        Message = "Firewall pipeline built with {RuleCount} rule(s): {Rules}")]
    public static partial void PipelineBuilt(ILogger logger, int ruleCount, string rules);
}

/// <summary>
/// Materialises a list of <see cref="IFirewallRule"/>s from a validated
/// <see cref="FirewallOptions"/> instance. Used by the AspNetCore DI extensions
/// when building the default pipeline.
/// </summary>
public sealed class FirewallOptionsBinder
{
    private readonly IOptions<FirewallOptions> _options;
    private readonly IGeoProvider? _geo;
    private readonly IEnumerable<IIpRangeProvider> _rangeProviders;
    private readonly ILogger<FirewallOptionsBinder> _logger;

    /// <summary>Constructs a new binder.</summary>
    public FirewallOptionsBinder(
        IOptions<FirewallOptions> options,
        IEnumerable<IIpRangeProvider> rangeProviders,
        ILogger<FirewallOptionsBinder> logger,
        IGeoProvider? geo = null)
    {
        Throw.IfNull(options);
        Throw.IfNull(rangeProviders);
        Throw.IfNull(logger);
        _options = options;
        _rangeProviders = rangeProviders;
        _logger = logger;
        _geo = geo;
    }

    /// <summary>Builds the rule list described by the bound options.</summary>
    public IReadOnlyList<IFirewallRule> BuildRules()
    {
        var o = _options.Value;
        var rules = new List<IFirewallRule>();

        if (o.Rules.AllowLocalhost)
            rules.Add(LocalhostAllowRule.Instance);

        var deniedIps = o.Rules.DeniedIps.Select(IPAddress.Parse).ToList();
        if (deniedIps.Count > 0) rules.Add(new IpDenyRule(deniedIps));

        var deniedCidrs = o.Rules.DeniedCidrs.Select(Cidr.Parse).ToList();
        if (deniedCidrs.Count > 0) rules.Add(new CidrDenyRule(deniedCidrs));

        if (_geo is not null && o.Rules.DeniedCountries.Count > 0)
            rules.Add(new CountryDenyRule(_geo, o.Rules.DeniedCountries));

        var allowedIps = o.Rules.AllowedIps.Select(IPAddress.Parse).ToList();
        if (allowedIps.Count > 0) rules.Add(new IpAllowRule(allowedIps));

        var allowedCidrs = o.Rules.AllowedCidrs.Select(Cidr.Parse).ToList();
        if (allowedCidrs.Count > 0) rules.Add(new CidrAllowRule(allowedCidrs));

        if (_geo is not null && o.Rules.AllowedCountries.Count > 0)
            rules.Add(new CountryAllowRule(_geo, o.Rules.AllowedCountries));

        foreach (var provider in _rangeProviders)
            rules.Add(new IpRangeProviderRule(provider));

        if (o.Rules.DefaultDeny)
            rules.Add(DefaultDenyRule.Instance);

        BinderLog.PipelineBuilt(_logger, rules.Count, string.Join(", ", rules.Select(r => $"{r.Name}#{r.Order}")));

        return rules;
    }
}
