using System.Collections.Frozen;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;

namespace Firewall.Rules;

/// <summary>Rejects requests whose remote IP is in the configured deny-list. Evaluates ahead of allow rules by convention (low order).</summary>
public sealed class IpDenyRule : IFirewallRule
{
    private readonly FrozenSet<IPAddress> _denied;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="IpDenyRule"/>.</summary>
    public IpDenyRule(IEnumerable<IPAddress> denied, string name = "IpDeny", int order = 10)
    {
        Throw.IfNull(denied);
        _denied = denied.ToFrozenSet();
        Name = name ?? throw new System.ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
    {
        var ip = context.RemoteIp;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return _denied.Contains(ip)
            ? new ValueTask<RuleEvaluation>(RuleEvaluation.Deny("ip deny-list match"))
            : new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
    }
}
