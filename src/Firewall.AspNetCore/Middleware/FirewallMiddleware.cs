using System;
using System.Globalization;
using System.Net;
using System.Threading.Tasks;
using Firewall.Internal;
using Firewall.Networking;
using Firewall.Pipeline;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Firewall.Middleware;

/// <summary>
/// ASP.NET Core middleware that evaluates each request against the firewall
/// pipeline and either short-circuits with the configured deny response or
/// calls the next delegate.
/// </summary>
public sealed class FirewallMiddleware
{
    private readonly RequestDelegate _next;
    private readonly FirewallPipeline _pipeline;
    private readonly IOptionsMonitor<FirewallOptions> _options;
    private readonly ILogger<FirewallMiddleware> _logger;
    private readonly ForwardedHeaderResolver _resolver;

    /// <summary>Instantiates a new middleware. Wired up by <c>UseMiddleware</c>.</summary>
    public FirewallMiddleware(
        RequestDelegate next,
        FirewallPipeline pipeline,
        IOptionsMonitor<FirewallOptions> options,
        ILogger<FirewallMiddleware> logger)
    {
        Throw.IfNull(next);
        Throw.IfNull(pipeline);
        Throw.IfNull(options);
        Throw.IfNull(logger);

        _next = next;
        _pipeline = pipeline;
        _options = options;
        _logger = logger;
        _resolver = BuildResolver(options.CurrentValue.TrustedProxies);
    }

    /// <summary>Executes the middleware against the supplied <see cref="HttpContext"/>.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        Throw.IfNull(context);

        var options = _options.CurrentValue;
        if (!options.Enabled)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var peer = context.Connection.RemoteIpAddress ?? IPAddress.None;
        var xff = context.Request.Headers.TryGetValue("X-Forwarded-For", out var hdr) ? hdr.ToString() : null;
        var resolved = _resolver.Resolve(peer, xff);

        var fwCtx = new FirewallContext(
            remoteIp: resolved,
            forwardedFor: xff,
            countryCode: null,
            scheme: context.Request.Scheme,
            method: context.Request.Method,
            path: context.Request.Path,
            headers: context.Request.Headers,
            services: context.RequestServices,
            transport: context);

        PipelineResult result;
        try
        {
            using var cts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            cts.CancelAfter(options.EvaluationTimeout);
            result = await _pipeline.EvaluateAsync(fwCtx, cts.Token).ConfigureAwait(false);
        }
        catch (FirewallRuleException ex)
        {
            FirewallLog.RuleFailed(_logger, ex.RuleName, ex);
            await WriteDenyAsync(context, options.OnDeny).ConfigureAwait(false);
            return;
        }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested)
        {
            FirewallLog.EvaluationTimedOut(_logger, options.EvaluationTimeout);
            await WriteDenyAsync(context, options.OnDeny).ConfigureAwait(false);
            return;
        }

        if (result.Evaluation.Decision == RuleDecision.Deny)
        {
            FirewallLog.RequestDenied(_logger, resolved, result.MatchedRule?.Name ?? "(unknown)", result.Evaluation.Reason ?? "(no reason)");
            await WriteDenyAsync(context, options.OnDeny).ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
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

    private static async Task WriteDenyAsync(HttpContext context, BlockResponseOptions options)
    {
        if (context.Response.HasStarted) return;

        context.Response.StatusCode = options.StatusCode;
        if (!string.IsNullOrEmpty(options.ContentType))
            context.Response.ContentType = options.ContentType;
        if (options.RetryAfterSeconds is { } seconds)
            context.Response.Headers["Retry-After"] = seconds.ToString(CultureInfo.InvariantCulture);
        if (!string.IsNullOrEmpty(options.Body))
            await context.Response.WriteAsync(options.Body, context.RequestAborted).ConfigureAwait(false);
    }
}

internal static partial class FirewallLog
{
    [LoggerMessage(EventId = 2000, Level = LogLevel.Warning,
        Message = "Firewall denied request from {RemoteIp}: rule {RuleName} → {Reason}")]
    public static partial void RequestDenied(ILogger logger, IPAddress remoteIp, string ruleName, string reason);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Error,
        Message = "Firewall rule {RuleName} threw during evaluation")]
    public static partial void RuleFailed(ILogger logger, string ruleName, System.Exception exception);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Warning,
        Message = "Firewall evaluation exceeded {Timeout}")]
    public static partial void EvaluationTimedOut(ILogger logger, System.TimeSpan timeout);
}
