using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Providers;
using MaxMind.Db;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using Microsoft.Extensions.Options;

namespace Firewall.Geo.MaxMind;

/// <summary>
/// MaxMind GeoIP2-backed implementation of <see cref="IGeoProvider"/>.
/// </summary>
public sealed class MaxMindGeoProvider : IGeoProvider, IDisposable
{
    private readonly DatabaseReader _reader;

    /// <inheritdoc/>
    public string Name => "maxmind";

    /// <summary>Constructs a new provider over the database at the configured path.</summary>
    public MaxMindGeoProvider(IOptions<MaxMindGeoOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var o = options.Value;
        if (string.IsNullOrWhiteSpace(o.DatabasePath))
            throw new InvalidOperationException("MaxMindGeoOptions.DatabasePath must be set.");
        _reader = new DatabaseReader(o.DatabasePath, FileAccessMode.MemoryMapped);
    }

    /// <inheritdoc/>
    public ValueTask<string?> GetCountryCodeAsync(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            return new ValueTask<string?>(_reader.Country(address).Country.IsoCode);
        }
        catch (AddressNotFoundException)
        {
            return new ValueTask<string?>((string?)null);
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _reader.Dispose();
}
