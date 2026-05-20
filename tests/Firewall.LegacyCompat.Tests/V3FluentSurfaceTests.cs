using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Firewall.LegacyCompat.Tests;

/// <summary>
/// Verifies the v3 fluent surface — <see cref="FirewallRulesEngine"/>,
/// <see cref="CIDRNotation"/>, <see cref="CountryCode"/> — still compiles
/// and produces working rules. Existing v3 consumer code must keep
/// working on v4 without modification (other than addressing the
/// [Obsolete] warnings on their own schedule).
/// </summary>
public sealed class V3FluentSurfaceTests
{
    [Fact]
    public void DenyAllAccess_returns_a_rule_that_denies_by_default()
    {
        var rule = FirewallRulesEngine.DenyAllAccess();

        EvaluateSync(rule, "1.2.3.4").Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public void ExceptFromLocalhost_admits_loopback()
    {
        var rule = FirewallRulesEngine.DenyAllAccess().ExceptFromLocalhost();

        EvaluateSync(rule, "127.0.0.1").Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "1.2.3.4").Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public void ExceptFromIPAddresses_admits_listed_addresses()
    {
        var rule = FirewallRulesEngine
            .DenyAllAccess()
            .ExceptFromIPAddresses(new List<IPAddress> { IPAddress.Parse("8.8.8.8") });

        EvaluateSync(rule, "8.8.8.8").Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "1.1.1.1").Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public void ExceptFromIPAddressRanges_admits_listed_cidrs()
    {
        var rule = FirewallRulesEngine
            .DenyAllAccess()
            .ExceptFromIPAddressRanges(new List<CIDRNotation>
            {
                CIDRNotation.Parse("10.0.0.0/8"),
            });

        EvaluateSync(rule, "10.42.42.42").Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "11.0.0.1").Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public void Full_v3_chain_admits_listed_and_denies_unknown()
    {
        var rule = FirewallRulesEngine
            .DenyAllAccess()
            .ExceptFromLocalhost()
            .ExceptFromIPAddresses(new[] { IPAddress.Parse("8.8.8.8") })
            .ExceptFromIPAddressRanges(new[] { CIDRNotation.Parse("10.0.0.0/8") });

        EvaluateSync(rule, "127.0.0.1").Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "8.8.8.8").Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "10.0.0.42").Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "1.2.3.4").Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public void ExceptWhen_treats_predicate_as_allow_rule()
    {
        var rule = FirewallRulesEngine
            .DenyAllAccess()
            .ExceptWhen(ctx => ctx.Request.Headers.ContainsKey("X-VIP"));

        EvaluateSync(rule, "1.2.3.4", headers => headers["X-VIP"] = "true")
            .Decision.Should().Be(RuleDecision.Allow);
        EvaluateSync(rule, "1.2.3.4").Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public void ExceptFromCloudflare_throws_with_migration_guidance()
    {
        // Marked [Obsolete(error: true)] so a direct call won't compile.
        // We invoke via reflection to exercise the runtime guidance.
        var rule = FirewallRulesEngine.DenyAllAccess();
        var method = typeof(FirewallRulesEngine).GetMethod(
            nameof(FirewallRulesEngine.ExceptFromCloudflare),
            new[] { typeof(IFirewallRule), typeof(string), typeof(string) })!;

        var act = () =>
        {
            try { method.Invoke(null, new object?[] { rule, null, null }); }
            catch (System.Reflection.TargetInvocationException tie) { throw tie.InnerException!; }
        };

        act.Should().Throw<NotSupportedException>()
            .WithMessage("*AddCloudflareProvider*");
    }

    [Fact]
    public void ExceptFromCountries_throws_with_migration_guidance()
    {
        var rule = FirewallRulesEngine.DenyAllAccess();
        var method = typeof(FirewallRulesEngine).GetMethod(
            nameof(FirewallRulesEngine.ExceptFromCountries),
            new[] { typeof(IFirewallRule), typeof(IList<CountryCode>) })!;

        var act = () =>
        {
            try { method.Invoke(null, new object?[] { rule, new List<CountryCode> { CountryCode.GB } }); }
            catch (System.Reflection.TargetInvocationException tie) { throw tie.InnerException!; }
        };

        act.Should().Throw<NotSupportedException>()
            .WithMessage("*IGeoProvider*");
    }

    [Fact]
    public void CIDRNotation_round_trips_through_Parse_and_ToString()
    {
        CIDRNotation.Parse("10.0.0.0/8").ToString().Should().Be("10.0.0.0/8");
        CIDRNotation.Parse("2001:db8::/32").ToString().Should().Be("2001:db8::/32");
    }

    [Fact]
    public void CIDRNotation_implicit_conversion_to_Cidr_works()
    {
        CIDRNotation legacy = CIDRNotation.Parse("10.0.0.0/8");
        Firewall.Networking.Cidr modern = legacy;
        modern.PrefixLength.Should().Be(8);
    }

    [Fact]
    public void IFirewallRule_IsAllowed_extension_still_works()
    {
        // v3 callers used the sync IsAllowed(HttpContext) overload. We kept
        // it as an [Obsolete] extension method that adapts to the async API.
        var rule = FirewallRulesEngine
            .DenyAllAccess()
            .ExceptFromIPAddresses(new[] { IPAddress.Parse("8.8.8.8") });

        BuildHttpContext("8.8.8.8").Then(rule.IsAllowed).Should().BeTrue();
        BuildHttpContext("1.1.1.1").Then(rule.IsAllowed).Should().BeFalse();
    }

    private static RuleEvaluation EvaluateSync(IFirewallRule rule, string ip, Action<IHeaderDictionary>? configureHeaders = null)
    {
        var http = BuildHttpContext(ip);
        configureHeaders?.Invoke(http.Request.Headers);
        var fwCtx = new FirewallContext(
            remoteIp: IPAddress.Parse(ip),
            forwardedFor: null,
            countryCode: null,
            scheme: "https",
            method: "GET",
            path: "/",
            headers: http.Request.Headers,
            services: http.RequestServices,
            transport: http);
        return rule.EvaluateAsync(fwCtx, CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    private static DefaultHttpContext BuildHttpContext(string ip)
    {
        var http = new DefaultHttpContext { RequestServices = new EmptyServiceProvider() };
        http.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        http.Request.Scheme = "https";
        http.Request.Method = "GET";
        http.Request.Path = "/";
        return http;
    }

    private sealed class EmptyServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}

internal static class TestExtensions
{
    public static TResult Then<T, TResult>(this T self, Func<T, TResult> next) => next(self);
}
