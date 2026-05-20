using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Firewall.Networking;

namespace Firewall.Rules;

/// <summary>Rejects requests whose remote IP falls within any of the configured CIDR ranges.</summary>
public sealed class CidrDenyRule : IFirewallRule
{
    private readonly CidrTrie _trie;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="CidrDenyRule"/>.</summary>
    public CidrDenyRule(IEnumerable<Cidr> deniedRanges, string name = "CidrDeny", int order = 20)
    {
        Throw.IfNull(deniedRanges);
        _trie = new CidrTrie();
        _trie.AddRange(deniedRanges);
        _trie.Build();
        Name = name ?? throw new System.ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
        => _trie.Contains(context.RemoteIp)
            ? new ValueTask<RuleEvaluation>(RuleEvaluation.Deny("cidr deny-list match"))
            : new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
}
