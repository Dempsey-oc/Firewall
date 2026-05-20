using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Firewall.Networking;
using Firewall.Providers;
using Microsoft.Extensions.Primitives;

namespace Firewall.Rules;

/// <summary>
/// Admits requests whose remote IP falls within an <see cref="IIpRangeProvider"/>'s
/// most recently published snapshot (e.g. Cloudflare's IP ranges).
/// </summary>
/// <remarks>
/// The rule subscribes to the provider's <see cref="IIpRangeProvider.WatchToken"/>
/// and rebuilds its internal trie atomically on each refresh. Reads remain lock-free.
/// </remarks>
public sealed class IpRangeProviderRule : IFirewallRule
{
    private readonly IIpRangeProvider _provider;
    private System.Collections.Frozen.FrozenSet<System.Net.IPAddress> _ipSet;
    private CidrTrie _trie;
    private IDisposable? _watch;

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public int Order { get; }

    /// <summary>Constructs a new rule over the given provider.</summary>
    public IpRangeProviderRule(IIpRangeProvider provider, int order = 300)
    {
        Throw.IfNull(provider);
        _provider = provider;
        _ipSet = System.Collections.Frozen.FrozenSet<System.Net.IPAddress>.Empty;
        _trie = new CidrTrie();
        Name = $"Provider:{provider.Name}";
        Order = order;
        Rebuild();
        Subscribe();
    }

    private void Subscribe()
    {
        _watch?.Dispose();
        _watch = ChangeToken.OnChange(() => _provider.WatchToken, Rebuild);
    }

    private void Rebuild()
    {
        var snap = _provider.Current;
        var ipSet = new System.Collections.Generic.HashSet<System.Net.IPAddress>(snap.IPAddresses).ToFrozenSet();
        var trie = new CidrTrie();
        foreach (var raw in snap.Cidrs)
            if (Cidr.TryParse(raw, out var cidr)) trie.Add(cidr);
        trie.Build();

        System.Threading.Volatile.Write(ref _ipSet, ipSet);
        System.Threading.Volatile.Write(ref _trie, trie);
    }

    /// <inheritdoc/>
    public ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken)
    {
        var ip = context.RemoteIp;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        var ips = System.Threading.Volatile.Read(ref _ipSet);
        if (ips.Contains(ip))
            return new ValueTask<RuleEvaluation>(RuleEvaluation.Allow($"{_provider.Name} ip match").WithTag("firewall.provider", _provider.Name));

        var trie = System.Threading.Volatile.Read(ref _trie);
        if (trie.Contains(ip))
            return new ValueTask<RuleEvaluation>(RuleEvaluation.Allow($"{_provider.Name} cidr match").WithTag("firewall.provider", _provider.Name));

        return new ValueTask<RuleEvaluation>(RuleEvaluation.Continue);
    }
}

file static class FrozenSetExtensions
{
    public static System.Collections.Frozen.FrozenSet<T> ToFrozenSet<T>(this System.Collections.Generic.HashSet<T> set)
        => System.Collections.Frozen.FrozenSet.ToFrozenSet<T>(set);
}
