using System.Collections.Frozen;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;

namespace Firewall.Rules;

/// <summary>Admits requests whose remote IP is in the configured allow-list.</summary>
public sealed class IpAllowRule : IFirewallRule
{
    private readonly FrozenSet<IPAddress> _allowed;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="IpAllowRule"/>.</summary>
    public IpAllowRule(IEnumerable<IPAddress> allowed, string name = "IpAllow", int order = 100)
    {
        Throw.IfNull(allowed);
        _allowed = allowed.ToFrozenSet();
        Name = name ?? throw new System.ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
    {
        var ip = context.RemoteIp;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return _allowed.Contains(ip)
            ? new ValueTask<RuleEvaluation>(RuleEvaluation.Allow("ip allow-list match"))
            : new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
    }
}
