using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.HealthChecks;
using Firewall.Pipeline;
using Firewall.Providers;
using Firewall.Rules;
using FluentAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Firewall.HealthChecks.Tests;

public sealed class FirewallHealthCheckTests
{
    private static readonly HealthCheckContext s_ctx = new()
    {
        Registration = new HealthCheckRegistration(
            "firewall",
            instance: new NoOpHealthCheck(),
            failureStatus: null,
            tags: null),
    };

    private sealed class NoOpHealthCheck : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(HealthCheckResult.Healthy());
    }

    [Fact]
    public async Task Empty_pipeline_with_no_providers_is_healthy()
    {
        var pipe = new FirewallPipeline(Array.Empty<IFirewallRule>());
        var sut = new FirewallHealthCheck(pipe, Array.Empty<IIpRangeProvider>(), DefaultMonitor());

        var result = await sut.CheckHealthAsync(s_ctx);

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Data.Should().ContainKey("pipeline.rules").WhoseValue.Should().Be(0);
    }

    [Fact]
    public async Task Fresh_provider_snapshot_is_healthy()
    {
        var pipe = new FirewallPipeline(new IFirewallRule[] { LocalhostAllowRule.Instance });
        var provider = new FakeProvider("cloudflare", new IpRangeSnapshot(
            new[] { IPAddress.Parse("1.1.1.1") },
            new[] { "1.1.1.0/24" },
            DateTimeOffset.UtcNow.AddMinutes(-1),
            etag: null));
        var sut = new FirewallHealthCheck(pipe, new[] { provider }, DefaultMonitor());

        var result = await sut.CheckHealthAsync(s_ctx);

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Data.Should().ContainKey("provider.cloudflare.ips").WhoseValue.Should().Be(1);
        result.Data.Should().ContainKey("provider.cloudflare.cidrs").WhoseValue.Should().Be(1);
        result.Data.Should().ContainKey("provider.cloudflare.stale").WhoseValue.Should().Be(false);
    }

    [Fact]
    public async Task Default_empty_snapshot_is_degraded()
    {
        // IpRangeSnapshot.Empty has FetchedAtUtc == MinValue, which fails the
        // freshness check by definition.
        var pipe = new FirewallPipeline(Array.Empty<IFirewallRule>());
        var provider = new FakeProvider("cloudflare", IpRangeSnapshot.Empty);
        var sut = new FirewallHealthCheck(pipe, new[] { provider }, DefaultMonitor());

        var result = await sut.CheckHealthAsync(s_ctx);

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("stale");
        result.Data.Should().ContainKey("provider.cloudflare.stale").WhoseValue.Should().Be(true);
    }

    [Fact]
    public async Task Snapshot_older_than_double_refresh_interval_is_degraded()
    {
        var pipe = new FirewallPipeline(Array.Empty<IFirewallRule>());
        var twoRefreshesAgo = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(40);
        var provider = new FakeProvider("cloudflare", new IpRangeSnapshot(
            Array.Empty<IPAddress>(),
            new[] { "1.1.1.0/24" },
            twoRefreshesAgo,
            etag: null));
        var sut = new FirewallHealthCheck(pipe, new[] { provider }, DefaultMonitor(TimeSpan.FromMinutes(15)));

        var result = await sut.CheckHealthAsync(s_ctx);

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task Mixed_fresh_and_stale_providers_overall_degraded()
    {
        var pipe = new FirewallPipeline(Array.Empty<IFirewallRule>());
        var fresh = new FakeProvider("a", new IpRangeSnapshot(
            Array.Empty<IPAddress>(), new[] { "10.0.0.0/8" }, DateTimeOffset.UtcNow, null));
        var stale = new FakeProvider("b", IpRangeSnapshot.Empty);
        var sut = new FirewallHealthCheck(pipe, new[] { fresh, stale }, DefaultMonitor());

        var result = await sut.CheckHealthAsync(s_ctx);

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Data.Should().ContainKey("provider.a.stale").WhoseValue.Should().Be(false);
        result.Data.Should().ContainKey("provider.b.stale").WhoseValue.Should().Be(true);
    }

    private static IOptionsMonitor<FirewallOptions> DefaultMonitor(TimeSpan? refresh = null)
    {
        var opts = new FirewallOptions { ProviderRefreshInterval = refresh ?? TimeSpan.FromMinutes(15) };
        return new MonitorStub(opts);
    }

    private sealed class MonitorStub : IOptionsMonitor<FirewallOptions>
    {
        public MonitorStub(FirewallOptions value) => CurrentValue = value;
        public FirewallOptions CurrentValue { get; }
        public FirewallOptions Get(string? name) => CurrentValue;
        public IDisposable OnChange(Action<FirewallOptions, string?> listener) => new Disp();
        private sealed class Disp : IDisposable { public void Dispose() { } }
    }

    private sealed class FakeProvider : IIpRangeProvider
    {
        public FakeProvider(string name, IpRangeSnapshot snapshot)
        {
            Name = name;
            Current = snapshot;
        }
        public string Name { get; }
        public IpRangeSnapshot Current { get; }
        public ValueTask RefreshAsync(CancellationToken ct) => ValueTask.CompletedTask;
        public IChangeToken WatchToken { get; } = new CancellationChangeToken(CancellationToken.None);
    }
}
