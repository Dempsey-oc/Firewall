using System.Collections.Generic;
using System.Linq;
using System.Net;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Firewall.Networking;

namespace Firewall.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class CidrTrieBenchmarks
{
    [Params(10, 1_000, 10_000)]
    public int RuleCount { get; set; }

    private CidrTrie _trie = null!;
    private List<Cidr> _linearList = null!;
    private IPAddress _hit = null!;
    private IPAddress _miss = null!;

    [GlobalSetup]
    public void Setup()
    {
        var rng = new System.Random(42);
        var cidrs = new List<Cidr>(RuleCount);
        for (var i = 0; i < RuleCount; i++)
        {
            var a = rng.Next(1, 224);
            var b = rng.Next(0, 256);
            cidrs.Add(Cidr.Parse($"{a}.{b}.0.0/16"));
        }

        _trie = new CidrTrie();
        _trie.AddRange(cidrs);
        _trie.Build();
        _linearList = cidrs;

        _hit = IPAddress.Parse($"{cidrs[RuleCount / 2].Address}");
        _miss = IPAddress.Parse("203.0.113.1"); // RFC 5737 test range
    }

    [Benchmark(Description = "Trie hit (O(W))")]
    public bool TrieHit() => _trie.Contains(_hit);

    [Benchmark(Description = "Trie miss (O(W))")]
    public bool TrieMiss() => _trie.Contains(_miss);

    [Benchmark(Baseline = true, Description = "Linear hit (O(N))")]
    public bool LinearHit() => _linearList.Any(c => c.Contains(_hit));

    [Benchmark(Description = "Linear miss (O(N))")]
    public bool LinearMiss() => _linearList.Any(c => c.Contains(_miss));
}
