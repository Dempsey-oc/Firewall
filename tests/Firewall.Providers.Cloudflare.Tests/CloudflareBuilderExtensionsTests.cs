using System.Linq;
using Firewall.DependencyInjection;
using Firewall.Providers;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Firewall.Providers.Cloudflare.Tests;

public sealed class CloudflareBuilderExtensionsTests
{
    [Fact]
    public void AddCloudflareProvider_registers_provider_and_hosted_service()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFirewall().AddCloudflareProvider();

        var sp = services.BuildServiceProvider();
        var provider = sp.GetRequiredService<CloudflareIpRangeProvider>();

        provider.Should().NotBeNull();
        sp.GetServices<IIpRangeProvider>().Should().ContainSingle()
            .Which.Should().BeSameAs(provider);
        services.Should().Contain(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
            && d.ImplementationType == typeof(CloudflareRefreshService));
    }

    [Fact]
    public void AddCloudflareProvider_applies_user_configuration()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFirewall().AddCloudflareProvider(o => o.RefreshInterval = System.TimeSpan.FromMinutes(7));

        var sp = services.BuildServiceProvider();
        var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<CloudflareOptions>>().Value;

        opts.RefreshInterval.Should().Be(System.TimeSpan.FromMinutes(7));
    }
}
