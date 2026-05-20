using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Networking;
using Firewall.Rules;
using Microsoft.AspNetCore.Http;

namespace Firewall;

/// <summary>
/// v3 compatibility shim. New code should compose <see cref="IFirewallRule"/>s
/// through DI (<c>services.AddFirewall()</c>) and bind options from configuration.
/// </summary>
[Obsolete("Use services.AddFirewall().Configure(...) for new code. FirewallRulesEngine will be removed in v5.")]
public static class FirewallRulesEngine
{
    /// <summary>Starts a v3-style rule chain ending in a default-deny.</summary>
    public static IFirewallRule DenyAllAccess() => new ChainedRule(DefaultDenyRule.Instance);

    /// <summary>Adds a localhost-allow segment.</summary>
    public static IFirewallRule ExceptFromLocalhost(this IFirewallRule rule)
        => Prepend(rule, LocalhostAllowRule.Instance);

    /// <summary>Adds an allow-list of explicit IPs.</summary>
    public static IFirewallRule ExceptFromIPAddresses(this IFirewallRule rule, IList<IPAddress> ipAddresses)
        => Prepend(rule, new IpAllowRule(ipAddresses));

    /// <summary>Adds an allow-list of CIDR ranges.</summary>
    public static IFirewallRule ExceptFromIPAddressRanges(this IFirewallRule rule, IList<CIDRNotation> cidrNotations)
        => Prepend(rule, new CidrAllowRule(cidrNotations.Select(c => (Cidr)c)));

    /// <summary>Adds a custom predicate as an allow rule.</summary>
    public static IFirewallRule ExceptWhen(this IFirewallRule rule, Func<HttpContext, bool> filter)
    {
        Func<FirewallContext, CancellationToken, ValueTask<RuleEvaluation>> evaluator = (ctx, _) =>
        {
            var http = ctx.Transport as HttpContext;
            if (http is null) return new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
            return new ValueTask<RuleEvaluation>(filter(http) ? RuleEvaluation.Allow("legacy predicate") : RuleEvaluation.Continue);
        };
        return Prepend(rule, new CustomRule(evaluator, "LegacyCustomRule"));
    }

    /// <summary>Cloudflare allow-listing is no longer fetched synchronously. Use <c>AddCloudflareProvider()</c> from the Firewall.Providers.Cloudflare package.</summary>
    [Obsolete("ExceptFromCloudflare blocked on async at startup. Use services.AddFirewall().AddCloudflareProvider() (Firewall.Providers.Cloudflare). Throws at runtime in v4.", error: true)]
    public static IFirewallRule ExceptFromCloudflare(this IFirewallRule rule, string? ipv4ListUrl = null, string? ipv6ListUrl = null)
        => throw new NotSupportedException("ExceptFromCloudflare has been replaced by AddCloudflareProvider() in Firewall.Providers.Cloudflare.");

    /// <summary>Country allow-listing now requires a geo provider. Use <c>AddMaxMindGeo()</c> from Firewall.Geo.MaxMind.</summary>
    [Obsolete("ExceptFromCountries required an embedded GeoLite2 DB that goes stale. Use services.AddFirewall().AddMaxMindGeo(...) and bind AllowedCountries via options. Throws at runtime in v4.", error: true)]
    public static IFirewallRule ExceptFromCountries(this IFirewallRule rule, IList<CountryCode> countries)
        => throw new NotSupportedException("ExceptFromCountries has been replaced by an IGeoProvider abstraction. See Firewall.Geo.MaxMind.");

    private static ChainedRule Prepend(IFirewallRule existing, IFirewallRule prepended)
        => existing is ChainedRule chain
            ? chain.Prepend(prepended)
            : new ChainedRule(existing).Prepend(prepended);

    private sealed class ChainedRule : IFirewallRule
    {
        private readonly List<IFirewallRule> _chain;

        public ChainedRule(IFirewallRule terminal) => _chain = new List<IFirewallRule> { terminal };

        public ChainedRule Prepend(IFirewallRule rule)
        {
            var c = new List<IFirewallRule>(_chain.Count + 1) { rule };
            c.AddRange(_chain);
            return new ChainedRule(c);
        }

        private ChainedRule(List<IFirewallRule> rules) => _chain = rules;

        public string Name => "LegacyChain";
        public int Order => 5000;

        public async ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
        {
            foreach (var rule in _chain)
            {
                var result = await rule.EvaluateAsync(context, cancellationToken).ConfigureAwait(false);
                if (result.Decision != RuleDecision.Continue) return result;
            }
            return RuleEvaluation.Deny("legacy default deny");
        }
    }
}
