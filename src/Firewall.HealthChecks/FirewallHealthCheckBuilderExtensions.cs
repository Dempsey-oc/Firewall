using System;
using System.Collections.Generic;
using Firewall.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.DependencyInjection;

namespace Firewall.HealthChecks;

/// <summary>DI extensions for the firewall health check.</summary>
public static class FirewallHealthCheckBuilderExtensions
{
    /// <summary>Registers the firewall <see cref="IHealthCheck"/>.</summary>
    /// <param name="builder">The firewall builder.</param>
    /// <param name="name">The health check name. Defaults to <c>"firewall"</c>.</param>
    /// <param name="failureStatus">The status to report when degraded.</param>
    /// <param name="tags">Optional tags applied to the health check.</param>
    public static IFirewallBuilder AddHealthCheck(
        this IFirewallBuilder builder,
        string name = "firewall",
        HealthStatus failureStatus = HealthStatus.Degraded,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddHealthChecks().AddCheck<FirewallHealthCheck>(name, failureStatus, tags ?? Array.Empty<string>());
        return builder;
    }
}
