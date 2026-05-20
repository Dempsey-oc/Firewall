using System.Diagnostics;
using System.Diagnostics.Metrics;
using Firewall.Diagnostics;

namespace Firewall.OpenTelemetry;

/// <summary>
/// OpenTelemetry-compatible implementation of <see cref="IFirewallTelemetry"/>.
/// Exposes static <see cref="ActivitySource"/> and <see cref="Meter"/> instances
/// that consumers register with their OTLP exporter configuration.
/// </summary>
public sealed class FirewallTelemetry : IFirewallTelemetry
{
    /// <summary>The activity source for firewall evaluation traces. Subscribe via <c>tracerBuilder.AddSource(FirewallTelemetry.ActivitySourceName)</c>.</summary>
    public const string ActivitySourceName = "Firewall";

    /// <summary>The meter for firewall metrics. Subscribe via <c>meterBuilder.AddMeter(FirewallTelemetry.MeterName)</c>.</summary>
    public const string MeterName = "Firewall";

    /// <summary>The activity source backing evaluation traces.</summary>
    public static readonly ActivitySource Activity = new(ActivitySourceName, ThisAssembly.InformationalVersion);

    /// <summary>The meter backing firewall metrics.</summary>
    public static readonly Meter Meter = new(MeterName, ThisAssembly.InformationalVersion);

    private static readonly Counter<long> s_evaluations =
        Meter.CreateCounter<long>("firewall.requests.evaluated", unit: "{request}", description: "Number of requests evaluated by the firewall.");

    private static readonly Counter<long> s_decisions =
        Meter.CreateCounter<long>("firewall.requests.decisions", unit: "{request}", description: "Terminal decisions taken by rules.");

    private static readonly Histogram<double> s_evaluationDuration =
        Meter.CreateHistogram<double>("firewall.evaluation.duration", unit: "ms", description: "Wall-clock time spent in a single rule evaluation.");

    private static readonly Histogram<double> s_providerRefresh =
        Meter.CreateHistogram<double>("firewall.provider.refresh.duration", unit: "ms", description: "Wall-clock time spent refreshing a provider snapshot.");

    /// <inheritdoc/>
    public Activity? StartEvaluationActivity(string ruleName)
        => Activity.StartActivity("firewall.rule.evaluate", ActivityKind.Internal)?.AddTag("firewall.rule.name", ruleName);

    /// <inheritdoc/>
    public void RecordDecision(string ruleName, RuleDecision decision, double elapsedMilliseconds)
    {
        s_evaluations.Add(1, new KeyValuePair<string, object?>("firewall.rule.name", ruleName));
        s_decisions.Add(1,
            new KeyValuePair<string, object?>("firewall.rule.name", ruleName),
            new KeyValuePair<string, object?>("firewall.decision", decision.ToString()));
        s_evaluationDuration.Record(elapsedMilliseconds,
            new KeyValuePair<string, object?>("firewall.rule.name", ruleName),
            new KeyValuePair<string, object?>("firewall.decision", decision.ToString()));
    }

    /// <inheritdoc/>
    public void RecordProviderRefresh(string providerName, bool succeeded, double elapsedMilliseconds)
    {
        s_providerRefresh.Record(elapsedMilliseconds,
            new KeyValuePair<string, object?>("firewall.provider", providerName),
            new KeyValuePair<string, object?>("firewall.refresh.succeeded", succeeded));
    }
}

internal static class ThisAssembly
{
    public const string InformationalVersion = "4.0.0";
}
