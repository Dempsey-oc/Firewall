using Firewall.Internal;
using Microsoft.Extensions.DependencyInjection;

namespace Firewall.DependencyInjection;

/// <summary>
/// Fluent builder returned by <c>services.AddFirewall()</c>. Provider packages
/// (Cloudflare, MaxMind, OpenTelemetry, …) hang their own extension methods off
/// this type so call sites read top-to-bottom.
/// </summary>
public interface IFirewallBuilder
{
    /// <summary>The underlying service collection.</summary>
    IServiceCollection Services { get; }
}

internal sealed class FirewallBuilder : IFirewallBuilder
{
    public FirewallBuilder(IServiceCollection services)
    {
        Throw.IfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
