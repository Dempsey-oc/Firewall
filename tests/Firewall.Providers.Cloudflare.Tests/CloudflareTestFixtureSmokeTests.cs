using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Diagnostics;
using Firewall.Providers.Cloudflare;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Firewall.Providers.Cloudflare.Tests;

/// <summary>
/// Smoke-level test that the WireMock fixture is wired up correctly. The
/// remaining tests in this folder rely on this pattern; if this one breaks,
/// nothing else here is meaningful.
/// </summary>
public sealed class CloudflareTestFixtureSmokeTests : IDisposable
{
    private readonly WireMockServer _server = WireMockServer.Start();

    [Fact]
    public async Task WireMock_serves_static_cloudflare_payload()
    {
        _server
            .Given(Request.Create().WithPath("/ips-v4").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody("173.245.48.0/20\n103.21.244.0/22\n"));

        using var http = new HttpClient { BaseAddress = new Uri(_server.Urls[0]) };
        var body = await http.GetStringAsync("/ips-v4");

        body.Should().Contain("173.245.48.0/20");
        body.Should().Contain("103.21.244.0/22");
    }

    [Fact]
    public void Provider_can_be_constructed_with_test_doubles()
    {
        var services = new ServiceCollection()
            .AddOptions<CloudflareOptions>().Configure(o => { }).Services
            .AddSingleton<IFirewallTelemetry>(NoOpFirewallTelemetry.Instance)
            .AddSingleton<ILogger<CloudflareIpRangeProvider>>(NullLogger<CloudflareIpRangeProvider>.Instance)
            .AddHttpClient("Firewall.Cloudflare").Services
            .AddSingleton<CloudflareIpRangeProvider>()
            .BuildServiceProvider();

        var provider = services.GetRequiredService<CloudflareIpRangeProvider>();
        provider.Name.Should().Be("cloudflare");
        provider.Current.Should().NotBeNull();
        provider.Current.IPAddresses.Should().BeEmpty();
        provider.WatchToken.Should().NotBeNull();
    }

    public void Dispose() => _server.Stop();
}
