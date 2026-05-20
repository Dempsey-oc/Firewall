using System;
using System.Collections.Generic;
using System.Net;
using Firewall.Networking;
using Microsoft.Extensions.Options;

namespace Firewall.Configuration;

/// <summary>
/// Cross-field validation of <see cref="FirewallOptions"/>. Registered automatically by
/// the AspNetCore DI extensions.
/// </summary>
public sealed class FirewallOptionsValidator : IValidateOptions<FirewallOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, FirewallOptions options)
    {
        var errors = new List<string>();

        if (options.ProviderRefreshInterval < TimeSpan.FromMinutes(1) || options.ProviderRefreshInterval > TimeSpan.FromDays(1))
            errors.Add($"{nameof(options.ProviderRefreshInterval)} must be between 1 minute and 1 day (was {options.ProviderRefreshInterval}).");

        if (options.EvaluationTimeout < TimeSpan.FromMilliseconds(10) || options.EvaluationTimeout > TimeSpan.FromSeconds(30))
            errors.Add($"{nameof(options.EvaluationTimeout)} must be between 10ms and 30s (was {options.EvaluationTimeout}).");

        if (options.OnDeny.StatusCode is < 400 or > 599)
            errors.Add($"OnDeny.StatusCode must be a 4xx or 5xx status code (was {options.OnDeny.StatusCode}).");

        ValidateIpList(options.Rules.AllowedIps, nameof(options.Rules.AllowedIps), errors);
        ValidateIpList(options.Rules.DeniedIps, nameof(options.Rules.DeniedIps), errors);
        ValidateCidrList(options.Rules.AllowedCidrs, nameof(options.Rules.AllowedCidrs), errors);
        ValidateCidrList(options.Rules.DeniedCidrs, nameof(options.Rules.DeniedCidrs), errors);
        ValidateCountryList(options.Rules.AllowedCountries, nameof(options.Rules.AllowedCountries), errors);
        ValidateCountryList(options.Rules.DeniedCountries, nameof(options.Rules.DeniedCountries), errors);

        ValidateIpList(options.TrustedProxies.KnownProxies, nameof(options.TrustedProxies.KnownProxies), errors);
        ValidateCidrList(options.TrustedProxies.KnownNetworks, nameof(options.TrustedProxies.KnownNetworks), errors);

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }

    private static void ValidateIpList(IList<string> ips, string memberName, List<string> errors)
    {
        for (var i = 0; i < ips.Count; i++)
        {
            if (!IPAddress.TryParse(ips[i], out _))
                errors.Add($"{memberName}[{i}] is not a valid IP: '{ips[i]}'.");
        }
    }

    private static void ValidateCidrList(IList<string> cidrs, string memberName, List<string> errors)
    {
        for (var i = 0; i < cidrs.Count; i++)
        {
            if (!Cidr.TryParse(cidrs[i], out _))
                errors.Add($"{memberName}[{i}] is not a valid CIDR: '{cidrs[i]}'.");
        }
    }

    private static void ValidateCountryList(IList<string> countries, string memberName, List<string> errors)
    {
        for (var i = 0; i < countries.Count; i++)
        {
            var code = countries[i];
            if (code is not { Length: 2 } || !char.IsLetter(code[0]) || !char.IsLetter(code[1]))
                errors.Add($"{memberName}[{i}] is not a valid ISO 3166 alpha-2 code: '{code}'.");
        }
    }
}
