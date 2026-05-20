using System;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;

namespace Firewall.Rules;

/// <summary>Adapter rule built from an inline delegate. Useful for prototyping and small bespoke checks.</summary>
public sealed class CustomRule : IFirewallRule
{
    private readonly Func<FirewallContext, CancellationToken, ValueTask<RuleEvaluation>> _evaluator;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="CustomRule"/>.</summary>
    public CustomRule(
        Func<FirewallContext, CancellationToken, ValueTask<RuleEvaluation>> evaluator,
        string name,
        int order = 5000)
    {
        Throw.IfNull(evaluator);
        _evaluator = evaluator;
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
        => _evaluator(context, cancellationToken);
}
