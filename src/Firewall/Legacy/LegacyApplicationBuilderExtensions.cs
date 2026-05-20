using System;
using Firewall.Diagnostics;
using Firewall.Middleware;
using Firewall.Pipeline;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Firewall;

/// <summary>
/// v3 compatibility shim. New code should call <c>services.AddFirewall()...</c>
/// and then <c>app.UseFirewall()</c> (no rule argument).
/// </summary>
public static class LegacyApplicationBuilderExtensions
{
    /// <summary>v3 compatibility shim: register a pre-built rule and the middleware in one call.</summary>
    [Obsolete("Configure rules via services.AddFirewall().Configure(...) and call app.UseFirewall() (no arguments).")]
    public static IApplicationBuilder UseFirewall(this IApplicationBuilder app, IFirewallRule rule)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(rule);

        var options = app.ApplicationServices.GetService<IOptionsMonitor<FirewallOptions>>()
                       ?? throw new InvalidOperationException("Firewall services not registered. Call services.AddFirewall() first.");
        var telemetry = app.ApplicationServices.GetService<IFirewallTelemetry>() ?? NoOpFirewallTelemetry.Instance;
        var pipeline = new FirewallPipeline(new[] { rule }, telemetry);
        return app.UseMiddleware<FirewallMiddleware>(pipeline, options);
    }

    /// <summary>v3 compatibility shim: register a pre-built rule and a deny delegate.</summary>
    [Obsolete("Configure rules and the deny response via services.AddFirewall().Configure(...).")]
    public static IApplicationBuilder UseFirewall(
        this IApplicationBuilder app,
        IFirewallRule rule,
        RequestDelegate accessDeniedDelegate)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(accessDeniedDelegate);
        return app.UseFirewall(rule);
    }
}
