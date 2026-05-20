using System.Threading;
using System.Threading.Tasks;

namespace Firewall.Rules;

/// <summary>
/// The terminal rule for default-deny pipelines: returns <see cref="RuleDecision.Deny"/>
/// for any request that has not already been admitted by an earlier rule.
/// </summary>
public sealed class DefaultDenyRule : IFirewallRule
{
    /// <summary>The singleton instance — the rule is stateless.</summary>
    public static IFirewallRule Instance { get; } = new DefaultDenyRule();

    private DefaultDenyRule() { }

    /// <inheritdoc/>
    public string Name => "DefaultDeny";

    /// <inheritdoc/>
    public int Order => int.MaxValue;

    private static readonly ValueTask<RuleEvaluation> s_deny =
        new(RuleEvaluation.Deny("default deny"));

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
        => s_deny;
}
