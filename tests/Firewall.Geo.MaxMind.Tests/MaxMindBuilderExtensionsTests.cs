using System;
using System.IO;
using Firewall.DependencyInjection;
using Firewall.Providers;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Firewall.Geo.MaxMind.Tests;

public sealed class MaxMindBuilderExtensionsTests
{
    private static readonly string s_fixturePath = Path.Combine(
        AppContext.BaseDirectory, "fixtures", "GeoIP2-Country-Test.mmdb");

    [Fact]
    public void AddMaxMindGeo_registers_provider_with_options()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFirewall().AddMaxMindGeo(o => o.DatabasePath = s_fixturePath);

        var sp = services.BuildServiceProvider();
        var geo = sp.GetRequiredService<IGeoProvider>();
        geo.Should().BeOfType<MaxMindGeoProvider>();

        var opts = sp.GetRequiredService<IOptions<MaxMindGeoOptions>>().Value;
        opts.DatabasePath.Should().Be(s_fixturePath);
    }

    [Fact]
    public void AddMaxMindGeo_throws_when_builder_is_null()
    {
        var act = () => Firewall.Geo.MaxMind.MaxMindBuilderExtensions.AddMaxMindGeo(null!, _ => { });
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddMaxMindGeo_throws_when_configure_is_null()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddFirewall();
        var act = () => builder.AddMaxMindGeo(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
