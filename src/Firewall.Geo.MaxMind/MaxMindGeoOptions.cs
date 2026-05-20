using System.ComponentModel.DataAnnotations;

namespace Firewall.Geo.MaxMind;

/// <summary>Configuration for the MaxMind geo provider.</summary>
public sealed class MaxMindGeoOptions
{
    /// <summary>The configuration section name. Defaults to <c>"Firewall:Geo:MaxMind"</c>.</summary>
    public const string SectionName = "Firewall:Geo:MaxMind";

    /// <summary>
    /// Absolute path to a MaxMind <c>.mmdb</c> file (GeoLite2-Country or GeoIP2-Country).
    /// </summary>
    /// <remarks>
    /// Operators are responsible for updating this file out-of-band (sidecar, init container, cron job).
    /// The package never ships an embedded database — it goes stale and licensing is non-trivial.
    /// </remarks>
    [Required]
    public string DatabasePath { get; set; } = string.Empty;

    /// <summary>Cache size for the underlying reader. Default 64 KiB worth of decoded objects.</summary>
    [Range(0, int.MaxValue)]
    public int CacheSize { get; set; } = 4096;
}
