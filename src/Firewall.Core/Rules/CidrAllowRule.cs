using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Firewall.Networking;

namespace Firewall.Rules;

/// <summary>Admits requests whose remote IP falls within any of the configured CIDR ranges.</summary>
public sealed class CidrAllowRule : IFirewallRule
{
    private readonly CidrTrie _trie;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new <see cref="CidrAllowRule"/>.</summary>
    public CidrAllowRule(IEnumerable<Cidr> allowedRanges, string name = "CidrAllow", int order = 200)
    {
        Throw.IfNull(allowedRanges);
        _trie = new CidrTrie();
        _trie.AddRange(allowedRanges);
        _trie.Build();
        Name = name ?? throw new System.ArgumentNullException(nameof(name));
        Order = order;
    }

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
        => _trie.Contains(context.RemoteIp)
            ? new ValueTask<RuleEvaluation>(RuleEvaluation.Allow("cidr allow-list match"))
            : new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
}
