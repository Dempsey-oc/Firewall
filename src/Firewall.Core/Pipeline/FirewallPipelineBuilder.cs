using System;
using System.Collections.Generic;
using Firewall.Diagnostics;
using Firewall.Internal;

namespace Firewall.Pipeline;

/// <summary>
/// Fluent builder for composing a <see cref="FirewallPipeline"/>.
/// </summary>
public sealed class FirewallPipelineBuilder
{
    private readonly List<IFirewallRule> _rules = [];
    private IFirewallTelemetry? _telemetry;

    /// <summary>The rules added to the builder so far, in insertion order.</summary>
    public IReadOnlyList<IFirewallRule> Rules => _rules;

    /// <summary>Appends a rule to the pipeline.</summary>
    public FirewallPipelineBuilder Add(IFirewallRule rule)
    {
        Throw.IfNull(rule);
        _rules.Add(rule);
        return this;
    }

    /// <summary>Configures the telemetry adapter for the built pipeline.</summary>
    public FirewallPipelineBuilder WithTelemetry(IFirewallTelemetry telemetry)
    {
        Throw.IfNull(telemetry);
        _telemetry = telemetry;
        return this;
    }

    /// <summary>Builds an immutable pipeline. The builder may be reused afterwards.</summary>
    public FirewallPipeline Build() => new(_rules, _telemetry);
}
