using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Firewall.DependencyInjection;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Firewall.AspNetCore.Tests;

public sealed class FirewallMiddlewareTests
{
    private static async Task<TestServer> BuildHostAsync(System.Action<FirewallOptions> configureFirewall, IPAddress? remoteIp = null)
    {
        var ip = remoteIp ?? IPAddress.Loopback;
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s =>
                {
                    s.AddFirewall().Configure(configureFirewall);
                })
                .Configure(app =>
                {
                    app.Use(async (ctx, next) =>
                    {
                        ctx.Connection.RemoteIpAddress = ip;
                        await next();
                    });
                    app.UseFirewall();
                    app.Run(ctx => ctx.Response.WriteAsync("ok"));
                }))
            .StartAsync().ConfigureAwait(false);
        return host.GetTestServer();
    }

    [Fact]
    public async Task Default_allows_localhost()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = true;
        });
        using var client = server.CreateClient();
        var response = await client.GetAsync("/");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Default_deny_blocks_unknown_ips()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = false;
        });
        using var client = server.CreateClient();
        var response = await client.GetAsync("/");
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Allow_listed_ip_passes()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = false;
            o.Rules.AllowedCidrs.Add("0.0.0.0/0");
        });
        using var client = server.CreateClient();
        var response = await client.GetAsync("/");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Deny_overrides_allow()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = true;
            o.Rules.DeniedCidrs.Add("127.0.0.0/8");
        });
        using var client = server.CreateClient();
        var response = await client.GetAsync("/");
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Disabled_firewall_admits_everything()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Enabled = false;
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = false;
        });
        using var client = server.CreateClient();
        var response = await client.GetAsync("/");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Custom_deny_status_is_honoured()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = false;
            o.OnDeny.StatusCode = 451;
            o.OnDeny.Body = "blocked for legal reasons";
            o.OnDeny.RetryAfterSeconds = 60;
        });
        using var client = server.CreateClient();
        var response = await client.GetAsync("/");
        response.StatusCode.Should().Be((HttpStatusCode)451);
        (await response.Content.ReadAsStringAsync()).Should().Be("blocked for legal reasons");
        response.Headers.RetryAfter!.Delta.Should().Be(System.TimeSpan.FromSeconds(60));
    }

    [Fact]
    public async Task X_Forwarded_For_ignored_for_untrusted_peer()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = true;
            o.TrustedProxies.ForwardLimit = 1;
            // No KnownProxies → the loopback peer isn't trusted to set XFF.
        });
        using var client = server.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/");
        req.Headers.Add("X-Forwarded-For", "8.8.8.8");
        var response = await client.SendAsync(req);
        response.StatusCode.Should().Be(HttpStatusCode.OK); // localhost rule still admits because XFF was ignored
    }

    [Fact]
    public async Task X_Forwarded_For_unwrapped_for_trusted_peer()
    {
        using var server = await BuildHostAsync(o =>
        {
            o.Rules.DefaultDeny = true;
            o.Rules.AllowLocalhost = true;
            o.TrustedProxies.ForwardLimit = 1;
            o.TrustedProxies.KnownNetworks.Add("127.0.0.0/8");
        });
        using var client = server.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/");
        req.Headers.Add("X-Forwarded-For", "8.8.8.8");
        var response = await client.SendAsync(req);
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }
}
