using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Diagnostics;
using Firewall.Internal;

namespace Firewall.Pipeline;

/// <summary>
/// An immutable, ordered chain of <see cref="IFirewallRule"/>s evaluated against
/// each request. Built once at startup and then evaluated lock-free.
/// </summary>
public sealed class FirewallPipeline
{
    private readonly ImmutableArray<IFirewallRule> _rules;
    private readonly IFirewallTelemetry _telemetry;

    /// <summary>The ordered rules contained in this pipeline. Public for diagnostic endpoints.</summary>
    public ImmutableArray<IFirewallRule> Rules => _rules;

    /// <summary>The number of rules in the pipeline.</summary>
    public int Count => _rules.Length;

    /// <summary>Constructs a pipeline from the supplied rules. Rules are sorted by <see cref="IFirewallRule.Order"/>.</summary>
    public FirewallPipeline(IEnumerable<IFirewallRule> rules, IFirewallTelemetry? telemetry = null)
    {
        Throw.IfNull(rules);
        _rules = rules
            .Where(r => r is not null)
            .OrderBy(r => r.Order)
            .ThenBy(r => r.Name, StringComparer.Ordinal)
            .ToImmutableArray();
        _telemetry = telemetry ?? NoOpFirewallTelemetry.Instance;
    }

    /// <summary>
    /// Evaluates the pipeline. Returns the first rule that produces a terminal
    /// <see cref="RuleDecision.Allow"/> or <see cref="RuleDecision.Deny"/>.
    /// </summary>
    /// <remarks>Returns a default <see cref="RuleEvaluation"/> (Continue) when no rule reaches a verdict.</remarks>
    public async ValueTask<PipelineResult> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
    {
        if (_rules.Length == 0)
            return new PipelineResult(MatchedRule: null, Evaluation: RuleEvaluation.Continue);

        for (var i = 0; i < _rules.Length; i++)
        {
            var rule = _rules[i];
            cancellationToken.ThrowIfCancellationRequested();

            var sw = ValueStopwatch.StartNew();
            using var activity = _telemetry.StartEvaluationActivity(rule.Name);
            RuleEvaluation evaluation;
            try
            {
                evaluation = await rule.EvaluateAsync(context, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                _telemetry.RecordDecision(rule.Name, RuleDecision.Deny, sw.GetElapsedTime().TotalMilliseconds);
                throw new FirewallRuleException(rule.Name, ex);
            }

            _telemetry.RecordDecision(rule.Name, evaluation.Decision, sw.GetElapsedTime().TotalMilliseconds);

            if (evaluation.Decision != RuleDecision.Continue)
                return new PipelineResult(rule, evaluation);
        }

        return new PipelineResult(MatchedRule: null, Evaluation: RuleEvaluation.Continue);
    }
}

/// <summary>The terminal result of a pipeline evaluation.</summary>
public readonly record struct PipelineResult(IFirewallRule? MatchedRule, RuleEvaluation Evaluation);

/// <summary>Thrown when a rule throws during evaluation. Wraps the original exception.</summary>
public sealed class FirewallRuleException : Exception
{
    /// <summary>The name of the rule that failed.</summary>
    public string RuleName { get; }

    /// <summary>Constructs a new <see cref="FirewallRuleException"/>.</summary>
    public FirewallRuleException(string ruleName, Exception inner)
        : base($"Rule '{ruleName}' threw during evaluation: {inner.Message}", inner)
    {
        RuleName = ruleName;
    }
}

internal readonly struct ValueStopwatch
{
    private static readonly double s_tickFrequency = (double)TimeSpan.TicksPerSecond / Stopwatch.Frequency;
    private readonly long _startTimestamp;

    private ValueStopwatch(long startTimestamp) => _startTimestamp = startTimestamp;

    public static ValueStopwatch StartNew() => new(Stopwatch.GetTimestamp());

    public TimeSpan GetElapsedTime()
    {
        var end = Stopwatch.GetTimestamp();
        var ticks = (long)((end - _startTimestamp) * s_tickFrequency);
        return new TimeSpan(ticks);
    }
}
