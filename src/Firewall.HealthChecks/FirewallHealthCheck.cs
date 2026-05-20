using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Pipeline;
using Firewall.Providers;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Firewall.HealthChecks;

/// <summary>
/// An ASP.NET Core health check that reports on the firewall pipeline and any registered providers.
/// </summary>
/// <remarks>
/// Returns <see cref="HealthStatus.Healthy"/> when every provider has fetched at least one non-empty
/// snapshot within twice <see cref="FirewallOptions.ProviderRefreshInterval"/>; otherwise
/// <see cref="HealthStatus.Degraded"/>.
/// </remarks>
public sealed class FirewallHealthCheck : IHealthCheck
{
    private readonly FirewallPipeline _pipeline;
    private readonly IEnumerable<IIpRangeProvider> _providers;
    private readonly IOptionsMonitor<FirewallOptions> _options;

    /// <summary>Constructs a new health check.</summary>
    public FirewallHealthCheck(FirewallPipeline pipeline, IEnumerable<IIpRangeProvider> providers, IOptionsMonitor<FirewallOptions> options)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _providers = providers ?? throw new ArgumentNullException(nameof(providers));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var data = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["pipeline.rules"] = _pipeline.Count,
            ["pipeline.rule_names"] = _pipeline.Rules.Select(r => r.Name).ToArray(),
        };

        var degraded = false;
        var staleThreshold = _options.CurrentValue.ProviderRefreshInterval * 2;

        foreach (var p in _providers)
        {
            var snap = p.Current;
            var ageOk = snap.FetchedAtUtc != DateTimeOffset.MinValue && DateTimeOffset.UtcNow - snap.FetchedAtUtc < staleThreshold;
            data[$"provider.{p.Name}.ips"] = snap.IPAddresses.Count;
            data[$"provider.{p.Name}.cidrs"] = snap.Cidrs.Count;
            data[$"provider.{p.Name}.fetched_at"] = snap.FetchedAtUtc;
            data[$"provider.{p.Name}.stale"] = !ageOk;
            if (!ageOk) degraded = true;
        }

        return Task.FromResult(degraded
            ? HealthCheckResult.Degraded("One or more firewall providers are stale.", data: data)
            : HealthCheckResult.Healthy("Firewall pipeline is healthy.", data: data));
    }
}
