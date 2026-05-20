using System;
using Firewall.DependencyInjection;
using Firewall.Internal;
using Firewall.Providers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http.Resilience;

namespace Firewall.Providers.Cloudflare;

/// <summary>
/// DI extensions for the Cloudflare provider.
/// </summary>
public static class CloudflareBuilderExtensions
{
    /// <summary>
    /// Registers the Cloudflare IP range provider along with its hosted
    /// refresh service, a resilient <see cref="System.Net.Http.HttpClient"/>,
    /// and an options binding from <c>"Firewall:Cloudflare"</c>.
    /// </summary>
    public static IFirewallBuilder AddCloudflareProvider(this IFirewallBuilder builder, Action<CloudflareOptions>? configure = null)
    {
        Throw.IfNull(builder);

        var b = builder.Services.AddOptions<CloudflareOptions>()
            .Configure(o => { })
            .ValidateDataAnnotations()
            .ValidateOnStart();
        if (configure is not null) b.PostConfigure(configure);

        builder.Services.TryAddSingleton<CloudflareIpRangeProvider>();
        builder.Services.AddSingleton<IIpRangeProvider>(sp => sp.GetRequiredService<CloudflareIpRangeProvider>());

        builder.Services.AddHttpClient("Firewall.Cloudflare", c =>
        {
            c.Timeout = TimeSpan.FromSeconds(30);
            c.DefaultRequestHeaders.UserAgent.ParseAdd("Firewall.Providers.Cloudflare/4.0");
        })
        .AddStandardResilienceHandler(o =>
        {
            o.AttemptTimeout.Timeout = TimeSpan.FromSeconds(10);
            o.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(60);
            o.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(60);
        });

        builder.Services.AddHostedService<CloudflareRefreshService>();

        return builder;
    }
}
