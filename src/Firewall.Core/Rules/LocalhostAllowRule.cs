using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Firewall.Rules;

/// <summary>Admits any request whose remote IP is the loopback address.</summary>
public sealed class LocalhostAllowRule : IFirewallRule
{
    /// <summary>The singleton instance — the rule is stateless.</summary>
    public static IFirewallRule Instance { get; } = new LocalhostAllowRule();

    private LocalhostAllowRule() { }

    /// <inheritdoc/>
    public string Name => "LocalhostAllow";

    /// <inheritdoc/>
    public int Order => 50;

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
        => IPAddress.IsLoopback(context.RemoteIp)
            ? new ValueTask<RuleEvaluation>(RuleEvaluation.Allow("loopback"))
            : new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
}
