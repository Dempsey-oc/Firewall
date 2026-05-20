using System;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Diagnostics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Firewall.Providers.Cloudflare.Tests;

/// <summary>
/// Tests for the hosted background service that refreshes the snapshot.
/// We never wait for the PeriodicTimer interval in CI — instead, we assert
/// that the immediate initial refresh runs once on start, and that the
/// service shuts down cleanly when its stopping token is signalled.
/// </summary>
public sealed class CloudflareRefreshServiceTests : IDisposable
{
    private readonly WireMockServer _server = WireMockServer.Start();

    [Fact]
    public async Task ExecuteAsync_performs_initial_refresh_immediately_on_start()
    {
        _server.Given(Request.Create().WithPath("/ips-v4")).RespondWith(Response.Create().WithBody("1.1.1.0/24\n"));
        _server.Given(Request.Create().WithPath("/ips-v6")).RespondWith(Response.Create().WithBody(string.Empty));

        var provider = BuildProvider();
        var service = new CloudflareRefreshService(
            provider,
            new OptionsMonitorStub(new CloudflareOptions { RefreshInterval = TimeSpan.FromHours(1) }),
            NullLogger<CloudflareRefreshService>.Instance);

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);

        // Initial refresh runs synchronously before the timer; wait briefly
        // for the awaited RefreshAsync to publish.
        for (var i = 0; i < 50 && provider.Current.IPAddresses.Count + provider.Current.Cidrs.Count == 0; i++)
            await Task.Delay(20, cts.Token);

        provider.Current.Cidrs.Should().Contain("1.1.1.0/24");

        await service.StopAsync(cts.Token);
    }

    [Fact]
    public async Task ExecuteAsync_swallows_initial_refresh_failure()
    {
        _server.Given(Request.Create().WithPath("/ips-v4")).RespondWith(Response.Create().WithStatusCode(500));

        var provider = BuildProvider();
        var service = new CloudflareRefreshService(
            provider,
            new OptionsMonitorStub(new CloudflareOptions { RefreshInterval = TimeSpan.FromHours(1) }),
            NullLogger<CloudflareRefreshService>.Instance);

        using var cts = new CancellationTokenSource();

        // Must not throw: the hosted-service contract is "log and keep going".
        await service.StartAsync(cts.Token);
        await service.StopAsync(cts.Token);

        provider.Current.IPAddresses.Should().BeEmpty();
    }

    private CloudflareIpRangeProvider BuildProvider()
    {
        var baseUrl = _server.Urls[0];
        var services = new ServiceCollection();
        services.AddOptions<CloudflareOptions>().Configure(o =>
        {
            o.IPv4Url = baseUrl + "/ips-v4";
            o.IPv6Url = baseUrl + "/ips-v6";
        });
        services.AddSingleton<IFirewallTelemetry>(NoOpFirewallTelemetry.Instance);
        services.AddSingleton(NullLogger<CloudflareIpRangeProvider>.Instance);
        services.AddHttpClient("Firewall.Cloudflare");
        services.AddSingleton<CloudflareIpRangeProvider>();
        return services.BuildServiceProvider().GetRequiredService<CloudflareIpRangeProvider>();
    }

    public void Dispose() => _server.Stop();

    private sealed class OptionsMonitorStub : IOptionsMonitor<CloudflareOptions>
    {
        public OptionsMonitorStub(CloudflareOptions value) => CurrentValue = value;
        public CloudflareOptions CurrentValue { get; }
        public CloudflareOptions Get(string? name) => CurrentValue;
        public IDisposable OnChange(Action<CloudflareOptions, string?> listener) => NullDisposable.Instance;
        private sealed class NullDisposable : IDisposable
        {
            public static IDisposable Instance { get; } = new NullDisposable();
            public void Dispose() { }
        }
    }
}
