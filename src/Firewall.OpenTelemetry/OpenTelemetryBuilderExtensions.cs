using System;
using Firewall.DependencyInjection;
using Firewall.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Firewall.OpenTelemetry;

/// <summary>DI extensions for wiring OpenTelemetry instrumentation.</summary>
public static class OpenTelemetryBuilderExtensions
{
    /// <summary>
    /// Replaces the no-op telemetry adapter with the OpenTelemetry-backed
    /// <see cref="FirewallTelemetry"/>. Consumers still need to register
    /// <c>FirewallTelemetry.ActivitySourceName</c> and <c>FirewallTelemetry.MeterName</c>
    /// with their tracer / meter provider builders.
    /// </summary>
    public static IFirewallBuilder AddOpenTelemetry(this IFirewallBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.Replace(ServiceDescriptor.Singleton<IFirewallTelemetry, FirewallTelemetry>());
        return builder;
    }
}
