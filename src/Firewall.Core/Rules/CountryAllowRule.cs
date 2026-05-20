using System.Collections.Frozen;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Firewall.Providers;

namespace Firewall.Rules;

/// <summary>Admits requests originating from any of the configured countries (ISO 3166 alpha-2).</summary>
/// <remarks>Resolves the country code via the supplied <see cref="IGeoProvider"/> on first observation in a request.</remarks>
public sealed class CountryAllowRule : IFirewallRule
{
    private readonly FrozenSet<string> _allowed;
    private readonly IGeoProvider _geo;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="CountryAllowRule"/>.</summary>
    public CountryAllowRule(IGeoProvider geo, IEnumerable<string> countryCodes, string name = "CountryAllow", int order = 5000)
    {
        Throw.IfNull(geo);
        Throw.IfNull(countryCodes);
        _geo = geo;
        _allowed = new HashSet<string>(countryCodes, System.StringComparer.OrdinalIgnoreCase).ToFrozenSet(System.StringComparer.OrdinalIgnoreCase);
        Name = name ?? throw new System.ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public async ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
    {
        var country = context.CountryCode ?? await _geo.GetCountryCodeAsync(context.RemoteIp, cancellationToken).ConfigureAwait(false);
        if (country is not null && _allowed.Contains(country))
            return RuleEvaluation.Allow($"country {country} allow-listed").WithTag("geo.country", country);
        return RuleEvaluation.Continue;
    }
}
