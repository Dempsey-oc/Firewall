using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Providers;
using Microsoft.Extensions.Caching.Hybrid;

namespace Firewall.Caching;

/// <summary>
/// Decorator that caches <see cref="IGeoProvider"/> lookups via <see cref="HybridCache"/>.
/// </summary>
public sealed class CachingGeoProviderDecorator : IGeoProvider
{
    private readonly IGeoProvider _inner;
    private readonly HybridCache _cache;
    private readonly HybridCacheEntryOptions _entryOptions;

    /// <inheritdoc/>
    public string Name => $"cached:{_inner.Name}";

    /// <summary>Constructs a new decorator.</summary>
    public CachingGeoProviderDecorator(IGeoProvider inner, HybridCache cache, HybridCacheEntryOptions? entryOptions = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _entryOptions = entryOptions ?? new HybridCacheEntryOptions
        {
            Expiration = TimeSpan.FromHours(1),
            LocalCacheExpiration = TimeSpan.FromMinutes(15),
        };
    }

    /// <inheritdoc/>
    public ValueTask<string?> GetCountryCodeAsync(IPAddress address, CancellationToken cancellationToken)
    {
        var key = $"firewall:geo:country:{address}";
        return _cache.GetOrCreateAsync(
            key,
            address,
            (ip, ct) => _inner.GetCountryCodeAsync(ip, ct),
            _entryOptions,
            cancellationToken: cancellationToken);
    }
}
