using System.Collections.Generic;
using System.Collections.Immutable;

namespace Firewall;

/// <summary>
/// The structured result of evaluating an <see cref="IFirewallRule"/>.
/// </summary>
public readonly record struct RuleEvaluation
{
    private static readonly ImmutableArray<KeyValuePair<string, object?>> s_emptyTags
        = ImmutableArray<KeyValuePair<string, object?>>.Empty;

    /// <summary>The terminal decision.</summary>
    public RuleDecision Decision { get; init; }

    /// <summary>A short, log-safe explanation for the decision. Optional.</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Activity / metric tags emitted by the rule. Treated as low-cardinality
    /// dimensions; do not put raw IPs or user identifiers here.
    /// </summary>
    public ImmutableArray<KeyValuePair<string, object?>> Tags { get; init; }

    /// <summary>The next rule must evaluate.</summary>
    public static RuleEvaluation Continue { get; } = new()
    {
        Decision = RuleDecision.Continue,
        Tags = s_emptyTags,
    };

    /// <summary>Admit the request and short-circuit the pipeline.</summary>
    public static RuleEvaluation Allow(string? reason = null) => new()
    {
        Decision = RuleDecision.Allow,
        Reason = reason,
        Tags = s_emptyTags,
    };

    /// <summary>Reject the request and short-circuit the pipeline.</summary>
    public static RuleEvaluation Deny(string? reason = null) => new()
    {
        Decision = RuleDecision.Deny,
        Reason = reason,
        Tags = s_emptyTags,
    };

    /// <summary>Return a copy of this evaluation with the given tag appended.</summary>
    public RuleEvaluation WithTag(string key, object? value) => new()
    {
        Decision = Decision,
        Reason = Reason,
        Tags = (Tags.IsDefault ? s_emptyTags : Tags).Add(new KeyValuePair<string, object?>(key, value)),
    };
}
