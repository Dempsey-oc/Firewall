using System.Net;
using System.Threading.Tasks;
using Firewall.Networking;
using Firewall.Pipeline;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Transforms;

namespace Firewall.Yarp;

/// <summary>
/// A YARP <see cref="RequestTransform"/> that evaluates the firewall pipeline
/// against the inbound request before it is proxied upstream.
/// </summary>
public sealed class FirewallTransform : RequestTransform
{
    private readonly FirewallPipeline _pipeline;
    private readonly IOptionsMonitor<FirewallOptions> _options;
    private readonly ForwardedHeaderResolver _resolver;

    /// <summary>Constructs the transform.</summary>
    public FirewallTransform(FirewallPipeline pipeline, IOptionsMonitor<FirewallOptions> options)
    {
        _pipeline = pipeline;
        _options = options;
        _resolver = BuildResolver(options.CurrentValue.TrustedProxies);
    }

    /// <inheritdoc/>
    public override async ValueTask ApplyAsync(RequestTransformContext context)
    {
        var http = context.HttpContext;
        var peer = http.Connection.RemoteIpAddress ?? IPAddress.None;
        var xff = http.Request.Headers.TryGetValue("X-Forwarded-For", out var hdr) ? hdr.ToString() : null;
        var resolved = _resolver.Resolve(peer, xff);

        var fwCtx = new FirewallContext(
            remoteIp: resolved,
            forwardedFor: xff,
            countryCode: null,
            scheme: http.Request.Scheme,
            method: http.Request.Method,
            path: http.Request.Path,
            headers: http.Request.Headers,
            services: http.RequestServices,
            transport: http);

        var result = await _pipeline.EvaluateAsync(fwCtx, http.RequestAborted).ConfigureAwait(false);
        if (result.Evaluation.Decision == RuleDecision.Deny)
        {
            http.Response.StatusCode = _options.CurrentValue.OnDeny.StatusCode;
            context.ProxyRequest.RequestUri = null;
        }
    }

    private static ForwardedHeaderResolver BuildResolver(TrustedProxyOptions options)
    {
        var proxies = new System.Collections.Generic.List<IPAddress>();
        foreach (var raw in options.KnownProxies)
            if (IPAddress.TryParse(raw, out var ip)) proxies.Add(ip);
        var networks = new System.Collections.Generic.List<Cidr>();
        foreach (var raw in options.KnownNetworks)
            if (Cidr.TryParse(raw, out var c)) networks.Add(c);
        return new ForwardedHeaderResolver(proxies, networks, options.ForwardLimit);
    }
}
