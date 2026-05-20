using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Microsoft.AspNetCore.Http;

namespace Firewall;

/// <summary>
/// A single, composable filter in the firewall pipeline.
/// </summary>
/// <remarks>
/// Implementations MUST be thread-safe — rules are resolved once and reused for the lifetime of the application.
/// Implementations SHOULD complete synchronously when no I/O is required (return a completed <see cref="ValueTask{TResult}"/>).
/// </remarks>
public interface IFirewallRule
{
    /// <summary>A stable, log-safe identifier for this rule. Used in metrics and traces.</summary>
    string Name { get; }

    /// <summary>
    /// Deterministic ordering hint within a pipeline. Lower values evaluate first.
    /// Default convention: 0–999 hot-path rules, 1_000–9_999 standard rules, 10_000+ slow / network-bound rules.
    /// </summary>
    int Order { get; }

    /// <summary>
    /// Evaluates the rule against the supplied context.
    /// </summary>
    /// <param name="context">The host-agnostic firewall context.</param>
    /// <param name="cancellationToken">Honoured by network-bound rules.</param>
    ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken cancellationToken);
}

/// <summary>
/// Convenience extension methods over <see cref="IFirewallRule"/> for legacy / synchronous integration paths.
/// </summary>
public static class FirewallRuleExtensions
{
    /// <summary>Adapter for code that needs a synchronous <see cref="HttpContext"/>-based view of a rule.</summary>
    public static bool IsAllowed(this IFirewallRule rule, HttpContext context)
    {
        Throw.IfNull(rule);
        Throw.IfNull(context);

        var fwCtx = new FirewallContext(
            remoteIp: context.Connection.RemoteIpAddress ?? IPAddress.None,
            forwardedFor: context.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) ? xff.ToString() : null,
            countryCode: null,
            scheme: context.Request.Scheme,
            method: context.Request.Method,
            path: context.Request.Path,
            headers: context.Request.Headers,
            services: context.RequestServices,
            transport: context);

        var evaluation = rule.EvaluateAsync(fwCtx, context.RequestAborted).AsTask().GetAwaiter().GetResult();
        return evaluation.Decision != RuleDecision.Deny;
    }
}
