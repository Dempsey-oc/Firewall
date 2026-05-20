using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Diagnostics;
using Firewall.Providers;
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
/// Behavioural tests for <see cref="CloudflareIpRangeProvider"/>: refresh,
/// change-token propagation, parse handling, telemetry, and failure paths.
/// </summary>
public sealed class CloudflareIpRangeProviderTests : IAsyncLifetime
{
    private readonly WireMockServer _server = WireMockServer.Start();
    private readonly RecordingTelemetry _telemetry = new();

    Task IAsyncLifetime.InitializeAsync() => Task.CompletedTask;

    Task IAsyncLifetime.DisposeAsync()
    {
        _server.Stop();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task RefreshAsync_populates_Current_from_remote_lists()
    {
        StubIpv4("173.245.48.0/20\n103.21.244.0/22\n198.51.100.7\n");
        StubIpv6("2400:cb00::/32\n");

        var provider = BuildProvider();

        await provider.RefreshAsync(CancellationToken.None);

        provider.Current.IPAddresses.Should().ContainSingle()
            .Which.ToString().Should().Be("198.51.100.7");
        provider.Current.Cidrs.Should().BeEquivalentTo(new[]
        {
            "173.245.48.0/20",
            "103.21.244.0/22",
            "2400:cb00::/32",
        });
        provider.Current.FetchedAtUtc.Should().BeAfter(DateTimeOffset.UtcNow.AddSeconds(-5));
    }

    [Fact]
    public async Task RefreshAsync_fires_WatchToken_callback()
    {
        StubIpv4("1.1.1.0/24\n");
        StubIpv6(string.Empty);
        var provider = BuildProvider();

        var firedCount = 0;
        var firstToken = provider.WatchToken;
        firstToken.RegisterChangeCallback(_ => Interlocked.Increment(ref firedCount), null!);

        await provider.RefreshAsync(CancellationToken.None);

        firedCount.Should().Be(1, "the snapshot change must publish on the original token exactly once");
        provider.WatchToken.Should().NotBeSameAs(firstToken, "a fresh token must replace the canceled one");
    }

    [Fact]
    public async Task Successive_refreshes_publish_independent_tokens()
    {
        StubIpv4("1.1.1.0/24\n");
        StubIpv6(string.Empty);
        var provider = BuildProvider();

        await provider.RefreshAsync(CancellationToken.None);
        var tokenAfterFirst = provider.WatchToken;
        await provider.RefreshAsync(CancellationToken.None);

        tokenAfterFirst.HasChanged.Should().BeTrue();
        provider.WatchToken.HasChanged.Should().BeFalse();
    }

    [Fact]
    public async Task RefreshAsync_records_provider_refresh_telemetry_on_success()
    {
        StubIpv4("1.1.1.0/24\n");
        StubIpv6(string.Empty);
        var provider = BuildProvider();

        await provider.RefreshAsync(CancellationToken.None);

        _telemetry.Refreshes.Should().ContainSingle()
            .Which.Should().Match<RefreshRecord>(r => r.Provider == "cloudflare" && r.Succeeded);
    }

    [Fact]
    public async Task RefreshAsync_records_failure_telemetry_and_rethrows()
    {
        _server
            .Given(Request.Create().WithPath("/ips-v4"))
            .RespondWith(Response.Create().WithStatusCode(500));

        var provider = BuildProvider();

        await FluentActions
            .Invoking(() => provider.RefreshAsync(CancellationToken.None).AsTask())
            .Should().ThrowAsync<HttpRequestException>();

        _telemetry.Refreshes.Should().ContainSingle()
            .Which.Should().Match<RefreshRecord>(r => r.Provider == "cloudflare" && !r.Succeeded);
        provider.Current.IPAddresses.Should().BeEmpty(
            "a failed refresh must NOT corrupt the last-known-good snapshot");
    }

    [Fact]
    public async Task RefreshAsync_uses_last_known_good_on_subsequent_failure()
    {
        StubIpv4("1.1.1.0/24\n");
        StubIpv6(string.Empty);
        var provider = BuildProvider();
        await provider.RefreshAsync(CancellationToken.None);
        var firstSnapshot = provider.Current;

        // Replace stub with a 500. Last-known-good must remain visible.
        _server.Reset();
        _server.Given(Request.Create().WithPath("/ips-v4")).RespondWith(Response.Create().WithStatusCode(500));

        await FluentActions
            .Invoking(() => provider.RefreshAsync(CancellationToken.None).AsTask())
            .Should().ThrowAsync<HttpRequestException>();

        provider.Current.Should().BeSameAs(firstSnapshot);
    }

    [Fact]
    public async Task Malformed_lines_are_skipped_silently()
    {
        StubIpv4("1.1.1.0/24\n\n  \nnot-an-ip\nthis/is/garbage\n2.2.2.2\n");
        StubIpv6(string.Empty);
        var provider = BuildProvider();

        await provider.RefreshAsync(CancellationToken.None);

        provider.Current.Cidrs.Should().Contain("1.1.1.0/24");
        provider.Current.Cidrs.Should().Contain("this/is/garbage", "the provider doesn't pre-validate; rule build does");
        provider.Current.IPAddresses.Select(ip => ip.ToString()).Should().Contain("2.2.2.2");
    }

    [Fact]
    public async Task RefreshAsync_honours_cancellation()
    {
        _server
            .Given(Request.Create().WithPath("/ips-v4"))
            .RespondWith(Response.Create().WithDelay(TimeSpan.FromSeconds(10)).WithBody("ignored"));
        StubIpv6(string.Empty);
        var provider = BuildProvider();

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await FluentActions
            .Invoking(() => provider.RefreshAsync(cts.Token).AsTask())
            .Should().ThrowAsync<OperationCanceledException>();
    }

    private void StubIpv4(string body) => _server
        .Given(Request.Create().WithPath("/ips-v4").UsingGet())
        .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

    private void StubIpv6(string body) => _server
        .Given(Request.Create().WithPath("/ips-v6").UsingGet())
        .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

    private CloudflareIpRangeProvider BuildProvider()
    {
        var baseUrl = _server.Urls[0];
        var services = new ServiceCollection();
        services.AddOptions<CloudflareOptions>().Configure(o =>
        {
            o.IPv4Url = baseUrl + "/ips-v4";
            o.IPv6Url = baseUrl + "/ips-v6";
        });
        services.AddSingleton<IFirewallTelemetry>(_telemetry);
        services.AddSingleton(NullLogger<CloudflareIpRangeProvider>.Instance);
        services.AddHttpClient("Firewall.Cloudflare");
        services.AddSingleton<CloudflareIpRangeProvider>();
        var sp = services.BuildServiceProvider();
        return sp.GetRequiredService<CloudflareIpRangeProvider>();
    }

    private sealed class RecordingTelemetry : IFirewallTelemetry
    {
        public List<RefreshRecord> Refreshes { get; } = new();
        public System.Diagnostics.Activity? StartEvaluationActivity(string ruleName) => null;
        public void RecordDecision(string ruleName, RuleDecision decision, double elapsedMilliseconds) { }
        public void RecordProviderRefresh(string providerName, bool succeeded, double elapsedMilliseconds)
            => Refreshes.Add(new RefreshRecord(providerName, succeeded, elapsedMilliseconds));
    }

    private sealed record RefreshRecord(string Provider, bool Succeeded, double Elapsed);
}
