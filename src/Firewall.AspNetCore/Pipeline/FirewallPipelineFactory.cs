using Firewall.Configuration;
using Firewall.Diagnostics;
using Firewall.Internal;

namespace Firewall.Pipeline;

/// <summary>
/// Builds the singleton <see cref="FirewallPipeline"/> registered in DI from
/// the validated options and the discovered rule / provider services.
/// </summary>
public sealed class FirewallPipelineFactory
{
    private readonly FirewallOptionsBinder _binder;
    private readonly IFirewallTelemetry _telemetry;

    /// <summary>Constructs a new factory.</summary>
    public FirewallPipelineFactory(FirewallOptionsBinder binder, IFirewallTelemetry telemetry)
    {
        Throw.IfNull(binder);
        Throw.IfNull(telemetry);
        _binder = binder;
        _telemetry = telemetry;
    }

    /// <summary>Materialises the pipeline from the validated options.</summary>
    public FirewallPipeline Build() => new(_binder.BuildRules(), _telemetry);
}
