using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Pipeline;
using Firewall.Rules;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Firewall.Core.Tests.Pipeline;

public sealed class FirewallPipelineTests
{
    private static FirewallContext Ctx(string ip)
    {
        return new FirewallContext(
            remoteIp: IPAddress.Parse(ip),
            forwardedFor: null,
            countryCode: null,
            scheme: "https",
            method: "GET",
            path: "/",
            headers: new HeaderDictionary(),
            services: new EmptyServiceProvider(),
            transport: null);
    }

    [Fact]
    public async Task Empty_pipeline_returns_continue()
    {
        var p = new FirewallPipeline(System.Array.Empty<IFirewallRule>());
        var r = await p.EvaluateAsync(Ctx("1.2.3.4"), default);
        r.Evaluation.Decision.Should().Be(RuleDecision.Continue);
    }

    [Fact]
    public async Task First_allow_short_circuits()
    {
        var p = new FirewallPipeline(new IFirewallRule[]
        {
            new IpAllowRule(new[] { IPAddress.Parse("1.2.3.4") }),
            DefaultDenyRule.Instance,
        });

        var r = await p.EvaluateAsync(Ctx("1.2.3.4"), default);
        r.Evaluation.Decision.Should().Be(RuleDecision.Allow);
        r.MatchedRule!.Name.Should().Be("IpAllow");
    }

    [Fact]
    public async Task First_deny_short_circuits()
    {
        var p = new FirewallPipeline(new IFirewallRule[]
        {
            new IpDenyRule(new[] { IPAddress.Parse("9.9.9.9") }),
            new IpAllowRule(new[] { IPAddress.Parse("9.9.9.9") }),
        });

        var r = await p.EvaluateAsync(Ctx("9.9.9.9"), default);
        r.Evaluation.Decision.Should().Be(RuleDecision.Deny);
        r.MatchedRule!.Name.Should().Be("IpDeny");
    }

    [Fact]
    public async Task Rules_evaluated_in_order_ascending()
    {
        var p = new FirewallPipeline(new IFirewallRule[]
        {
            new IpAllowRule(new[] { IPAddress.Parse("1.2.3.4") }, "Late", order: 1000),
            new IpDenyRule(new[] { IPAddress.Parse("1.2.3.4") }, "Early", order: 10),
        });

        var r = await p.EvaluateAsync(Ctx("1.2.3.4"), default);
        r.MatchedRule!.Name.Should().Be("Early");
        r.Evaluation.Decision.Should().Be(RuleDecision.Deny);
    }

    [Fact]
    public async Task Throwing_rule_surfaces_as_FirewallRuleException()
    {
        var p = new FirewallPipeline(new IFirewallRule[]
        {
            new ThrowingRule(),
        });

        var act = async () => await p.EvaluateAsync(Ctx("1.2.3.4"), default);
        await act.Should().ThrowAsync<FirewallRuleException>().Where(e => e.RuleName == "Throwing");
    }

    private sealed class ThrowingRule : IFirewallRule
    {
        public string Name => "Throwing";
        public int Order => 0;
        public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
            => throw new System.InvalidOperationException("boom");
    }

    private sealed class EmptyServiceProvider : System.IServiceProvider
    {
        public object? GetService(System.Type serviceType) => null;
    }
}
