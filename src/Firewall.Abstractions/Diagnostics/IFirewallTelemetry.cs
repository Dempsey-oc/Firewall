using System.Diagnostics;

namespace Firewall.Diagnostics;

/// <summary>
/// Adapter for emitting firewall metrics, traces, and structured logs.
/// </summary>
/// <remarks>
/// The default no-op implementation is used when the <c>Firewall.OpenTelemetry</c> package is not referenced.
/// </remarks>
public interface IFirewallTelemetry
{
    /// <summary>Starts a new evaluation activity, if one is being listened for.</summary>
    Activity? StartEvaluationActivity(string ruleName);

    /// <summary>Records a terminal decision for the supplied rule.</summary>
    void RecordDecision(string ruleName, RuleDecision decision, double elapsedMilliseconds);

    /// <summary>Records that a provider refresh occurred.</summary>
    void RecordProviderRefresh(string providerName, bool succeeded, double elapsedMilliseconds);
}

/// <summary>A no-op <see cref="IFirewallTelemetry"/> used when no concrete telemetry adapter is registered.</summary>
public sealed class NoOpFirewallTelemetry : IFirewallTelemetry
{
    /// <summary>The singleton instance.</summary>
    public static IFirewallTelemetry Instance { get; } = new NoOpFirewallTelemetry();

    private NoOpFirewallTelemetry() { }

    /// <inheritdoc/>
    public Activity? StartEvaluationActivity(string ruleName) => null;

    /// <inheritdoc/>
    public void RecordDecision(string ruleName, RuleDecision decision, double elapsedMilliseconds) { }

    /// <inheritdoc/>
    public void RecordProviderRefresh(string providerName, bool succeeded, double elapsedMilliseconds) { }
}
