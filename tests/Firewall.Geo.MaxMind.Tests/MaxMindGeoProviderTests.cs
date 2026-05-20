using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Firewall.Geo.MaxMind.Tests;

/// <summary>
/// Tests for <see cref="MaxMindGeoProvider"/> using the redistributable
/// GeoIP2-Country-Test fixture from MaxMind's MaxMind-DB GitHub repository.
/// </summary>
public sealed class MaxMindGeoProviderTests
{
    private static readonly string s_fixturePath = Path.Combine(
        AppContext.BaseDirectory, "fixtures", "GeoIP2-Country-Test.mmdb");

    [Fact]
    public void Constructor_throws_when_DatabasePath_is_blank()
    {
        var act = () => new MaxMindGeoProvider(
            Options.Create(new MaxMindGeoOptions { DatabasePath = "" }));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*DatabasePath*must be set*");
    }

    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new MaxMindGeoProvider(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_when_file_does_not_exist()
    {
        var act = () => new MaxMindGeoProvider(
            Options.Create(new MaxMindGeoOptions { DatabasePath = "/no/such/file.mmdb" }));

        act.Should().Throw<Exception>(
            "MaxMind's DatabaseReader surfaces FileNotFoundException; we don't catch it because it's fatal at startup");
    }

    [Fact]
    public void Name_is_stable_and_log_safe()
    {
        using var sut = NewProvider();
        sut.Name.Should().Be("maxmind");
    }

    [Fact]
    public async Task GetCountryCodeAsync_returns_country_for_addresses_in_the_database()
    {
        // 81.2.69.142 is one of MaxMind's documented test addresses (GB) in
        // GeoIP2-Country-Test.mmdb. See the MaxMind/MaxMind-DB-Writer-perl
        // test fixtures.
        using var sut = NewProvider();

        var country = await sut.GetCountryCodeAsync(IPAddress.Parse("81.2.69.142"), CancellationToken.None);

        country.Should().NotBeNullOrWhiteSpace();
        country!.Length.Should().Be(2, "ISO 3166 alpha-2");
    }

    [Fact]
    public async Task GetCountryCodeAsync_returns_null_for_addresses_not_in_database()
    {
        // 203.0.113.0/24 is RFC 5737 documentation space — MaxMind's test DB
        // does not have an entry, so an AddressNotFoundException is thrown
        // internally and converted to null.
        using var sut = NewProvider();

        var country = await sut.GetCountryCodeAsync(IPAddress.Parse("203.0.113.7"), CancellationToken.None);

        country.Should().BeNull();
    }

    [Fact]
    public async Task GetCountryCodeAsync_is_safe_to_call_repeatedly()
    {
        using var sut = NewProvider();

        for (var i = 0; i < 64; i++)
            _ = await sut.GetCountryCodeAsync(IPAddress.Parse("81.2.69.142"), CancellationToken.None);

        // Survived 64 reads — the memory-mapped reader is reused and not torn down.
    }

    [Fact]
    public void Dispose_releases_the_DatabaseReader()
    {
        var sut = NewProvider();
        sut.Dispose();

        var act = () => sut.GetCountryCodeAsync(IPAddress.Parse("81.2.69.142"), CancellationToken.None).AsTask().GetAwaiter().GetResult();
        act.Should().Throw<Exception>("the underlying DatabaseReader has been disposed");
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        var sut = NewProvider();
        sut.Dispose();
        var act = () => sut.Dispose();
        act.Should().NotThrow();
    }

    private static MaxMindGeoProvider NewProvider()
        => new(Options.Create(new MaxMindGeoOptions { DatabasePath = s_fixturePath }));
}
