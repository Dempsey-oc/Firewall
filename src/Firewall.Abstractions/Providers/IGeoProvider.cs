using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Firewall.Providers;

/// <summary>
/// Supplies geolocation lookups for IP addresses.
/// </summary>
public interface IGeoProvider
{
    /// <summary>A stable, log-safe identifier (e.g. <c>"maxmind"</c>, <c>"ipinfo"</c>).</summary>
    string Name { get; }

    /// <summary>Resolves the ISO 3166 alpha-2 country code for <paramref name="address"/>.</summary>
    /// <returns>The country code, or <see langword="null"/> if it cannot be resolved.</returns>
    ValueTask<string?> GetCountryCodeAsync(IPAddress address, CancellationToken cancellationToken);
}
