using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Networking;
using Firewall.Providers;
using Firewall.Rules;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Firewall.Core.Tests.Rules;

public sealed class RuleTests
{
    private static FirewallContext Ctx(string ip, string? country = null)
    {
        var headers = new HeaderDictionary();
        return new FirewallContext(
            remoteIp: IPAddress.Parse(ip),
            forwardedFor: null,
            countryCode: country,
            scheme: "https",
            method: "GET",
            path: "/",
            headers: headers,
            services: new EmptyServiceProvider(),
            transport: null);
    }

    [Fact]
    public async Task IpAllowRule_admits_listed_ips()
    {
        var rule = new IpAllowRule(new[] { IPAddress.Parse("1.2.3.4") });
        (await rule.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Allow);
        (await rule.EvaluateAsync(Ctx("1.2.3.5"), default)).Decision.Should().Be(RuleDecision.Continue);
    }

    [Fact]
    public async Task IpDenyRule_rejects_listed_ips()
    {
        var rule = new IpDenyRule(new[] { IPAddress.Parse("9.9.9.9") });
        (await rule.EvaluateAsync(Ctx("9.9.9.9"), default)).Decision.Should().Be(RuleDecision.Deny);
        (await rule.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Continue);
    }

    [Fact]
    public async Task CidrAllowRule_admits_in_range()
    {
        var rule = new CidrAllowRule(new[] { Cidr.Parse("10.0.0.0/8") });
        (await rule.EvaluateAsync(Ctx("10.0.0.1"), default)).Decision.Should().Be(RuleDecision.Allow);
        (await rule.EvaluateAsync(Ctx("11.0.0.1"), default)).Decision.Should().Be(RuleDecision.Continue);
    }

    [Fact]
    public async Task LocalhostAllowRule_matches_loopback()
    {
        var rule = LocalhostAllowRule.Instance;
        (await rule.EvaluateAsync(Ctx("127.0.0.1"), default)).Decision.Should().Be(RuleDecision.Allow);
        (await rule.EvaluateAsync(Ctx("::1"), default)).Decision.Should().Be(RuleDecision.Allow);
        (await rule.EvaluateAsync(Ctx("8.8.8.8"), default)).Decision.Should().Be(RuleDecision.Continue);
    }

    [Fact]
    public async Task DefaultDenyRule_always_denies()
    {
        var rule = DefaultDenyRule.Instance;
        (await rule.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Deny);
        (await rule.EvaluateAsync(Ctx("127.0.0.1"), default)).Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public async Task CountryAllowRule_uses_geo_provider()
    {
        var geo = new FakeGeoProvider("US");
        var rule = new CountryAllowRule(geo, new[] { "US", "GB" });
        (await rule.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Allow);

        var geo2 = new FakeGeoProvider("RU");
        var rule2 = new CountryAllowRule(geo2, new[] { "US", "GB" });
        (await rule2.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Continue);
    }

    [Fact]
    public async Task CountryDenyRule_uses_geo_provider()
    {
        var geo = new FakeGeoProvider("KP");
        var rule = new CountryDenyRule(geo, new[] { "KP", "IR" });
        (await rule.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public async Task CountryRule_uses_context_country_when_set()
    {
        var geo = new ExplodingGeoProvider();
        var rule = new CountryAllowRule(geo, new[] { "US" });
        (await rule.EvaluateAsync(Ctx("1.2.3.4", country: "US"), default)).Decision.Should().Be(RuleDecision.Allow);
    }

    [Fact]
    public async Task CustomRule_passes_through_delegate()
    {
        var rule = new CustomRule((ctx, _) => new ValueTask<RuleEvaluation>(
            ctx.Method == "POST" ? RuleEvaluation.Deny("no posts") : RuleEvaluation.Continue), "NoPost");

        (await rule.EvaluateAsync(Ctx("1.2.3.4"), default)).Decision.Should().Be(RuleDecision.Continue);
    }

    private sealed class FakeGeoProvider : IGeoProvider
    {
        private readonly string? _country;
        public FakeGeoProvider(string? country) => _country = country;
        public string Name => "fake";
        public ValueTask<string?> GetCountryCodeAsync(IPAddress address, CancellationToken cancellationToken)
            => new(_country);
    }

    private sealed class ExplodingGeoProvider : IGeoProvider
    {
        public string Name => "exploding";
        public ValueTask<string?> GetCountryCodeAsync(IPAddress address, CancellationToken cancellationToken)
            => throw new System.InvalidOperationException("Should not be called when country is preset.");
    }

    private sealed class EmptyServiceProvider : System.IServiceProvider
    {
        public object? GetService(System.Type serviceType) => null;
    }
}
