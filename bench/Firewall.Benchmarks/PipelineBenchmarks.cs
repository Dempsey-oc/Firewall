using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Firewall.Networking;
using Firewall.Pipeline;
using Firewall.Rules;
using Microsoft.AspNetCore.Http;

namespace Firewall.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
public class PipelineBenchmarks
{
    private FirewallPipeline _pipeline = null!;
    private FirewallContext _hitCtx;
    private FirewallContext _missCtx;

    [GlobalSetup]
    public void Setup()
    {
        var cidrs = new List<Cidr>();
        for (var i = 0; i < 1000; i++)
            cidrs.Add(Cidr.Parse($"10.{i % 256}.{(i / 256) % 256}.0/24"));

        _pipeline = new FirewallPipeline(new IFirewallRule[]
        {
            LocalhostAllowRule.Instance,
            new IpDenyRule(new[] { IPAddress.Parse("9.9.9.9") }),
            new CidrAllowRule(cidrs),
            DefaultDenyRule.Instance,
        });

        var headers = new HeaderDictionary();
        _hitCtx = new FirewallContext(IPAddress.Parse("10.0.0.1"), null, null, "https", "GET", "/", headers, new EmptyServiceProvider());
        _missCtx = new FirewallContext(IPAddress.Parse("203.0.113.1"), null, null, "https", "GET", "/", headers, new EmptyServiceProvider());
    }

    [Benchmark(Description = "Allow path (matches CIDR rule)")]
    public async Task<RuleDecision> AllowPath()
    {
        var r = await _pipeline.EvaluateAsync(_hitCtx, default);
        return r.Evaluation.Decision;
    }

    [Benchmark(Description = "Deny path (default deny)")]
    public async Task<RuleDecision> DenyPath()
    {
        var r = await _pipeline.EvaluateAsync(_missCtx, default);
        return r.Evaluation.Decision;
    }

    private sealed class EmptyServiceProvider : System.IServiceProvider
    {
        public object? GetService(System.Type serviceType) => null;
    }
}
