using System;
using Firewall.Configuration;
using Firewall.Diagnostics;
using Firewall.Internal;
using Firewall.Pipeline;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Firewall.DependencyInjection;

/// <summary>
/// Entry-point DI extensions for the Firewall package.
/// </summary>
public static class FirewallServiceCollectionExtensions
{
    /// <summary>
    /// Registers the firewall middleware and rule engine.
    /// </summary>
    /// <remarks>
    /// The returned <see cref="IFirewallBuilder"/> is chained with provider /
    /// observability / cache extension methods to compose a full configuration.
    /// </remarks>
    public static IFirewallBuilder AddFirewall(this IServiceCollection services)
    {
        Throw.IfNull(services);

        services.AddOptions();
        services.AddLogging();
        services.TryAddSingleton<IFirewallTelemetry>(NoOpFirewallTelemetry.Instance);
        services.TryAddSingleton<IValidateOptions<FirewallOptions>, FirewallOptionsValidator>();
        services.TryAddSingleton<FirewallOptionsBinder>();
        services.TryAddSingleton<FirewallPipelineFactory>();
        services.TryAddSingleton<FirewallPipeline>(sp => sp.GetRequiredService<FirewallPipelineFactory>().Build());

        return new FirewallBuilder(services);
    }

    /// <summary>Binds <see cref="FirewallOptions"/> from the named configuration section. Defaults to <c>"Firewall"</c>.</summary>
    public static IFirewallBuilder BindConfiguration(this IFirewallBuilder builder, IConfiguration configuration, string sectionName = FirewallOptions.SectionName)
    {
        Throw.IfNull(builder);
        Throw.IfNull(configuration);

        var section = configuration.GetSection(sectionName);
        builder.Services
            .AddOptions<FirewallOptions>()
            .Bind(section)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return builder;
    }

    /// <summary>Configures <see cref="FirewallOptions"/> programmatically.</summary>
    public static IFirewallBuilder Configure(this IFirewallBuilder builder, Action<FirewallOptions> configure)
    {
        Throw.IfNull(builder);
        Throw.IfNull(configure);

        builder.Services
            .AddOptions<FirewallOptions>()
            .Configure(configure)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return builder;
    }
}
