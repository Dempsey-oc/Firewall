using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Firewall.Pipeline;
using Firewall.Rules;
using Firewall.Yarp;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Transforms;

namespace Firewall.Yarp.Tests;

public sealed class FirewallTransformTests
{
    [Fact]
    public async Task Allow_decision_leaves_proxy_request_intact()
    {
        var pipeline = new FirewallPipeline(new IFirewallRule[]
        {
            LocalhostAllowRule.Instance,
        });
        var ctx = BuildTransformContext(IPAddress.Loopback);
        var originalUri = ctx.ProxyRequest.RequestUri;

        var sut = new FirewallTransform(pipeline, BuildOptions());
        await sut.ApplyAsync(ctx);

        ctx.ProxyRequest.RequestUri.Should().BeSameAs(originalUri);
        ctx.HttpContext.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Deny_decision_zeroes_proxy_request_uri_and_sets_status()
    {
        var pipeline = new FirewallPipeline(new IFirewallRule[]
        {
            new IpDenyRule(new[] { IPAddress.Parse("8.8.8.8") }),
            DefaultDenyRule.Instance,
        });
        var ctx = BuildTransformContext(IPAddress.Parse("8.8.8.8"));

        var sut = new FirewallTransform(pipeline, BuildOptions());
        await sut.ApplyAsync(ctx);

        ctx.ProxyRequest.RequestUri.Should().BeNull("YARP treats a null RequestUri as 'do not proxy'");
        ctx.HttpContext.Response.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task Continue_decision_does_not_modify_proxy_request()
    {
        // No rule fires; pipeline returns Continue. Treat that as "let YARP
        // proxy the request" — the transform must not mutate.
        var pipeline = new FirewallPipeline(System.Array.Empty<IFirewallRule>());
        var ctx = BuildTransformContext(IPAddress.Parse("1.2.3.4"));
        var originalUri = ctx.ProxyRequest.RequestUri;

        var sut = new FirewallTransform(pipeline, BuildOptions());
        await sut.ApplyAsync(ctx);

        ctx.ProxyRequest.RequestUri.Should().BeSameAs(originalUri);
        ctx.HttpContext.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Custom_deny_status_is_honoured()
    {
        var pipeline = new FirewallPipeline(new IFirewallRule[] { DefaultDenyRule.Instance });
        var ctx = BuildTransformContext(IPAddress.Parse("1.2.3.4"));

        var sut = new FirewallTransform(pipeline, BuildOptions(o => o.OnDeny.StatusCode = 451));
        await sut.ApplyAsync(ctx);

        ctx.HttpContext.Response.StatusCode.Should().Be(451);
    }

    [Fact]
    public async Task Untrusted_peer_xff_is_ignored()
    {
        var pipeline = new FirewallPipeline(new IFirewallRule[]
        {
            new IpDenyRule(new[] { IPAddress.Parse("8.8.8.8") }),
            LocalhostAllowRule.Instance,
        });
        var ctx = BuildTransformContext(IPAddress.Loopback);
        ctx.HttpContext.Request.Headers["X-Forwarded-For"] = "8.8.8.8";

        var sut = new FirewallTransform(pipeline, BuildOptions(o => o.TrustedProxies.ForwardLimit = 1));
        await sut.ApplyAsync(ctx);

        ctx.HttpContext.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Trusted_peer_xff_is_honoured()
    {
        var pipeline = new FirewallPipeline(new IFirewallRule[]
        {
            new IpDenyRule(new[] { IPAddress.Parse("8.8.8.8") }),
            LocalhostAllowRule.Instance,
        });
        var ctx = BuildTransformContext(IPAddress.Loopback);
        ctx.HttpContext.Request.Headers["X-Forwarded-For"] = "8.8.8.8";

        var sut = new FirewallTransform(pipeline, BuildOptions(o =>
        {
            o.TrustedProxies.ForwardLimit = 1;
            o.TrustedProxies.KnownNetworks.Add("127.0.0.0/8");
        }));
        await sut.ApplyAsync(ctx);

        ctx.HttpContext.Response.StatusCode.Should().Be(403);
    }

    private static RequestTransformContext BuildTransformContext(IPAddress remoteIp)
    {
        var http = new DefaultHttpContext
        {
            RequestServices = new EmptyServiceProvider(),
        };
        http.Connection.RemoteIpAddress = remoteIp;
        http.Request.Scheme = "https";
        http.Request.Method = "GET";
        http.Request.Path = "/api/widgets";
        return new RequestTransformContext
        {
            HttpContext = http,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://upstream/api/widgets"),
            Path = "/api/widgets",
            Query = new QueryTransformContext(http.Request),
        };
    }

    private sealed class EmptyServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }

    private static IOptionsMonitor<FirewallOptions> BuildOptions(Action<FirewallOptions>? configure = null)
    {
        var opts = new FirewallOptions();
        configure?.Invoke(opts);
        return new MonitorStub(opts);
    }

    private sealed class MonitorStub : IOptionsMonitor<FirewallOptions>
    {
        public MonitorStub(FirewallOptions value) => CurrentValue = value;
        public FirewallOptions CurrentValue { get; }
        public FirewallOptions Get(string? name) => CurrentValue;
        public IDisposable OnChange(Action<FirewallOptions, string?> listener) => new Disp();
        private sealed class Disp : IDisposable { public void Dispose() { } }
    }
}
