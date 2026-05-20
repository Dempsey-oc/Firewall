using Firewall.DependencyInjection;
using Firewall.Diagnostics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Firewall.OpenTelemetry.Tests;

public sealed class OpenTelemetryBuilderExtensionsTests
{
    [Fact]
    public void AddOpenTelemetry_replaces_noop_telemetry_with_real_adapter()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFirewall();
        // Sanity-check the default registration before replacement.
        services.BuildServiceProvider().GetRequiredService<IFirewallTelemetry>()
            .Should().BeSameAs(NoOpFirewallTelemetry.Instance);

        services.AddFirewall().AddOpenTelemetry();

        services.BuildServiceProvider().GetRequiredService<IFirewallTelemetry>()
            .Should().BeOfType<FirewallTelemetry>();
    }
}
