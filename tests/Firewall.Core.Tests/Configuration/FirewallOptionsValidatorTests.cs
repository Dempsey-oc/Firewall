using Firewall.Configuration;
using FluentAssertions;
using Xunit;

namespace Firewall.Core.Tests.Configuration;

public sealed class FirewallOptionsValidatorTests
{
    private readonly FirewallOptionsValidator _sut = new();

    [Fact]
    public void Defaults_are_valid()
    {
        _sut.Validate(null, new FirewallOptions()).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Invalid_ip_fails()
    {
        var o = new FirewallOptions();
        o.Rules.AllowedIps.Add("not.an.ip");
        var r = _sut.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("AllowedIps");
    }

    [Fact]
    public void Invalid_cidr_fails()
    {
        var o = new FirewallOptions();
        o.Rules.AllowedCidrs.Add("nope/x");
        _sut.Validate(null, o).Failed.Should().BeTrue();
    }

    [Fact]
    public void Invalid_country_fails()
    {
        var o = new FirewallOptions();
        o.Rules.AllowedCountries.Add("ZZZ");
        _sut.Validate(null, o).Failed.Should().BeTrue();
    }

    [Fact]
    public void Refresh_interval_out_of_range_fails()
    {
        var o = new FirewallOptions { ProviderRefreshInterval = System.TimeSpan.FromSeconds(1) };
        _sut.Validate(null, o).Failed.Should().BeTrue();
    }

    [Fact]
    public void Status_code_out_of_range_fails()
    {
        var o = new FirewallOptions { OnDeny = { StatusCode = 200 } };
        _sut.Validate(null, o).Failed.Should().BeTrue();
    }
}
