using System;
using Firewall.DependencyInjection;
using Firewall.Providers;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;

namespace Firewall.Caching;

/// <summary>DI extensions for HybridCache integration.</summary>
public static class HybridCacheBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="HybridCache"/> and decorates any registered <see cref="IGeoProvider"/>
    /// with a caching layer. Bring your own L2 distributed cache (Redis, SQL, etc.) via
    /// the usual <c>AddStackExchangeRedisCache</c>-style registrations before calling this.
    /// </summary>
    public static IFirewallBuilder AddHybridCache(this IFirewallBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

#pragma warning disable EXTEXP0018
        builder.Services.AddHybridCache();
#pragma warning restore EXTEXP0018

        builder.Services.Decorate<IGeoProvider, CachingGeoProviderDecorator>();
        return builder;
    }

    internal static IServiceCollection Decorate<TService, TDecorator>(this IServiceCollection services)
        where TService : class
        where TDecorator : class, TService
    {
        for (var i = services.Count - 1; i >= 0; i--)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType != typeof(TService)) continue;

            var inner = descriptor;
            services[i] = ServiceDescriptor.Describe(
                typeof(TService),
                sp =>
                {
                    var innerInstance = (TService)CreateInstance(sp, inner);
                    return ActivatorUtilities.CreateInstance<TDecorator>(sp, innerInstance);
                },
                descriptor.Lifetime);
            return services;
        }

        throw new InvalidOperationException($"No registration for {typeof(TService).Name} to decorate.");
    }

    private static object CreateInstance(IServiceProvider sp, ServiceDescriptor descriptor)
    {
        if (descriptor.ImplementationInstance is not null) return descriptor.ImplementationInstance;
        if (descriptor.ImplementationFactory is not null) return descriptor.ImplementationFactory(sp);
        return ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType!);
    }
}
