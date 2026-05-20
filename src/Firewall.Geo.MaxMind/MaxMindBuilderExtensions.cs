using System;
using Firewall.DependencyInjection;
using Firewall.Providers;
using Microsoft.Extensions.DependencyInjection;

namespace Firewall.Geo.MaxMind;

/// <summary>DI extensions for the MaxMind geo provider.</summary>
public static class MaxMindBuilderExtensions
{
    /// <summary>Registers the MaxMind <see cref="IGeoProvider"/>.</summary>
    public static IFirewallBuilder AddMaxMindGeo(this IFirewallBuilder builder, Action<MaxMindGeoOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.AddOptions<MaxMindGeoOptions>()
            .Configure(configure)
            .ValidateDataAnnotations()
            .ValidateOnStart();
        builder.Services.AddSingleton<IGeoProvider, MaxMindGeoProvider>();
        return builder;
    }
}
