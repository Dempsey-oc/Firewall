using System;
using Firewall.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Firewall.Yarp;

/// <summary>DI extensions for the YARP transform.</summary>
public static class YarpBuilderExtensions
{
    /// <summary>Adds the firewall transform to every YARP route by default.</summary>
    public static IFirewallBuilder AddYarpIntegration(this IFirewallBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSingleton<ITransformProvider, FirewallTransformProvider>();
        return builder;
    }
}

internal sealed class FirewallTransformProvider : ITransformProvider
{
    public void ValidateRoute(TransformRouteValidationContext context) { }
    public void ValidateCluster(TransformClusterValidationContext context) { }

    public void Apply(TransformBuilderContext context)
    {
        context.RequestTransforms.Add(context.Services.GetRequiredService<FirewallTransform>());
    }
}
