using System.Collections.Frozen;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Firewall.Providers;

namespace Firewall.Rules;

/// <summary>Rejects requests originating from any of the configured countries (ISO 3166 alpha-2).</summary>
public sealed class CountryDenyRule : IFirewallRule
{
    private readonly FrozenSet<string> _denied;
    private readonly IGeoProvider _geo;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="CountryDenyRule"/>.</summary>
    public CountryDenyRule(IGeoProvider geo, IEnumerable<string> countryCodes, string name = "CountryDeny", int order = 4000)
    {
        Throw.IfNull(geo);
        Throw.IfNull(countryCodes);
        _geo = geo;
        _denied = new HashSet<string>(countryCodes, System.StringComparer.OrdinalIgnoreCase).ToFrozenSet(System.StringComparer.OrdinalIgnoreCase);
        Name = name ?? throw new System.ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public async ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
    {
        var country = context.CountryCode ?? await _geo.GetCountryCodeAsync(context.RemoteIp, cancellationToken).ConfigureAwait(false);
        if (country is not null && _denied.Contains(country))
            return RuleEvaluation.Deny($"country {country} deny-listed").WithTag("geo.country", country);
        return RuleEvaluation.Continue;
    }
}
