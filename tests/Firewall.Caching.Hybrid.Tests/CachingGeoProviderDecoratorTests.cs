using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Caching;
using Firewall.Providers;
using FluentAssertions;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Firewall.Caching.Hybrid.Tests;

public sealed class CachingGeoProviderDecoratorTests
{
    [Fact]
    public void Name_is_prefixed_with_cached()
    {
        var inner = new CountingGeoProvider("maxmind", returns: "US");
        var hc = BuildHybridCache();

        var sut = new CachingGeoProviderDecorator(inner, hc);

        sut.Name.Should().Be("cached:maxmind");
    }

    [Fact]
    public async Task First_call_invokes_inner_provider()
    {
        var inner = new CountingGeoProvider("maxmind", returns: "US");
        var hc = BuildHybridCache();
        var sut = new CachingGeoProviderDecorator(inner, hc);

        var result = await sut.GetCountryCodeAsync(IPAddress.Parse("1.1.1.1"), CancellationToken.None);

        result.Should().Be("US");
        inner.Calls.Should().Be(1);
    }

    [Fact]
    public async Task Repeat_call_for_same_ip_hits_cache_not_inner()
    {
        var inner = new CountingGeoProvider("maxmind", returns: "US");
        var hc = BuildHybridCache();
        var sut = new CachingGeoProviderDecorator(inner, hc);

        await sut.GetCountryCodeAsync(IPAddress.Parse("1.1.1.1"), CancellationToken.None);
        await sut.GetCountryCodeAsync(IPAddress.Parse("1.1.1.1"), CancellationToken.None);
        await sut.GetCountryCodeAsync(IPAddress.Parse("1.1.1.1"), CancellationToken.None);

        inner.Calls.Should().Be(1, "subsequent lookups for the same IP must be served from HybridCache");
    }

    [Fact]
    public async Task Different_ips_each_hit_inner_once()
    {
        var inner = new CountingGeoProvider("maxmind", returns: "US");
        var hc = BuildHybridCache();
        var sut = new CachingGeoProviderDecorator(inner, hc);

        await sut.GetCountryCodeAsync(IPAddress.Parse("1.1.1.1"), CancellationToken.None);
        await sut.GetCountryCodeAsync(IPAddress.Parse("8.8.8.8"), CancellationToken.None);
        await sut.GetCountryCodeAsync(IPAddress.Parse("9.9.9.9"), CancellationToken.None);

        inner.Calls.Should().Be(3);
    }

    private static HybridCache BuildHybridCache()
    {
#pragma warning disable EXTEXP0018 // HybridCache is in-preview
        var services = new ServiceCollection().AddHybridCache().Services;
#pragma warning restore EXTEXP0018
        return services.BuildServiceProvider().GetRequiredService<HybridCache>();
    }

    private sealed class CountingGeoProvider : IGeoProvider
    {
        private readonly string? _returns;
        public CountingGeoProvider(string name, string? returns) { Name = name; _returns = returns; }
        public string Name { get; }
        public int Calls { get; private set; }
        public ValueTask<string?> GetCountryCodeAsync(IPAddress address, CancellationToken cancellationToken)
        {
            Calls++;
            return new ValueTask<string?>(_returns);
        }
    }
}
