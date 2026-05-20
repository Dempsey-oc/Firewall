using Firewall.Internal;
using Firewall.Middleware;
using Microsoft.AspNetCore.Builder;

namespace Firewall;

/// <summary>
/// <see cref="IApplicationBuilder"/> extensions for the firewall middleware.
/// </summary>
public static class FirewallApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the firewall middleware to the request pipeline. Should be placed
    /// after global exception handling and before authentication / authorization.
    /// </summary>
    public static IApplicationBuilder UseFirewall(this IApplicationBuilder app)
    {
        Throw.IfNull(app);
        return app.UseMiddleware<FirewallMiddleware>();
    }
}
