using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Diagnostics;
using Firewall.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Firewall.Providers.Cloudflare;

/// <summary>
/// An <see cref="IIpRangeProvider"/> that fetches Cloudflare's IPv4 and IPv6
/// ranges and caches them as the current snapshot.
/// </summary>
/// <remarks>
/// Refreshes are driven by <c>CloudflareRefreshService</c> (a hosted background
/// service) on a schedule configured via <see cref="CloudflareOptions.RefreshInterval"/>.
/// </remarks>
public sealed class CloudflareIpRangeProvider : IIpRangeProvider, IDisposable
{
    /// <summary>Releases the cancellation token source backing the change token.</summary>
    public void Dispose()
    {
        Volatile.Read(ref _changeCts)?.Dispose();
    }

    private readonly IHttpClientFactory _clients;
    private readonly IOptionsMonitor<CloudflareOptions> _options;
    private readonly IFirewallTelemetry _telemetry;
    private readonly ILogger<CloudflareIpRangeProvider> _logger;

    private IpRangeSnapshot _current = IpRangeSnapshot.Empty;
    private CancellationTokenSource _changeCts = new();

    /// <inheritdoc/>
    public string Name => "cloudflare";

    /// <inheritdoc/>
    public IpRangeSnapshot Current => Volatile.Read(ref _current);

    /// <inheritdoc/>
    public IChangeToken WatchToken => new CancellationChangeToken(_changeCts.Token);

    /// <summary>Constructs a new <see cref="CloudflareIpRangeProvider"/>.</summary>
    public CloudflareIpRangeProvider(
        IHttpClientFactory clients,
        IOptionsMonitor<CloudflareOptions> options,
        IFirewallTelemetry telemetry,
        ILogger<CloudflareIpRangeProvider> logger)
    {
        _clients = clients ?? throw new ArgumentNullException(nameof(clients));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public async ValueTask RefreshAsync(CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        var ok = false;
        try
        {
            var opts = _options.CurrentValue;
            var client = _clients.CreateClient("Firewall.Cloudflare");

            var (ips4, cidrs4) = await FetchAsync(client, opts.IPv4Url, cancellationToken).ConfigureAwait(false);
            var (ips6, cidrs6) = await FetchAsync(client, opts.IPv6Url, cancellationToken).ConfigureAwait(false);

            var ips = new List<IPAddress>(ips4.Count + ips6.Count);
            ips.AddRange(ips4);
            ips.AddRange(ips6);

            var cidrs = new List<string>(cidrs4.Count + cidrs6.Count);
            cidrs.AddRange(cidrs4);
            cidrs.AddRange(cidrs6);

            var snapshot = new IpRangeSnapshot(ips, cidrs, DateTimeOffset.UtcNow, etag: null);

            Volatile.Write(ref _current, snapshot);
            var old = Interlocked.Exchange(ref _changeCts, new CancellationTokenSource());
            old.Cancel();
            old.Dispose();
            ok = true;

            CloudflareLog.Refreshed(_logger, ips.Count, cidrs.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            CloudflareLog.RefreshFailed(_logger, ex);
            throw;
        }
        finally
        {
            _telemetry.RecordProviderRefresh(Name, ok, sw.Elapsed.TotalMilliseconds);
        }
    }

    private static async Task<(IReadOnlyList<IPAddress>, IReadOnlyList<string>)> FetchAsync(HttpClient client, string url, CancellationToken ct)
    {
#if NET8_0_OR_GREATER
        var text = await client.GetStringAsync(url, ct).ConfigureAwait(false);
#else
        var text = await client.GetStringAsync(url).ConfigureAwait(false);
#endif
        var ips = new List<IPAddress>();
        var cidrs = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.Contains('/')) cidrs.Add(line);
            else if (IPAddress.TryParse(line, out var ip)) ips.Add(ip);
        }
        return (ips, cidrs);
    }
}

internal static class CloudflareLog
{
    private static readonly Action<ILogger, int, int, Exception?> s_refreshed =
        LoggerMessage.Define<int, int>(LogLevel.Information, new EventId(3000, nameof(Refreshed)),
            "Cloudflare refresh succeeded: {IpCount} IPs, {CidrCount} CIDRs");

    private static readonly Action<ILogger, Exception?> s_refreshFailed =
        LoggerMessage.Define(LogLevel.Error, new EventId(3001, nameof(RefreshFailed)),
            "Cloudflare refresh failed");

    public static void Refreshed(ILogger logger, int ipCount, int cidrCount) => s_refreshed(logger, ipCount, cidrCount, null);
    public static void RefreshFailed(ILogger logger, Exception exception) => s_refreshFailed(logger, exception);
}
