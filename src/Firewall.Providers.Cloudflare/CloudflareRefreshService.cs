using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Firewall.Providers.Cloudflare;

/// <summary>
/// Hosted background service that periodically refreshes the Cloudflare IP
/// range snapshot. Honours <see cref="CloudflareOptions.BlockOnStartup"/> when
/// <c>true</c>: the host startup is delayed until the first successful refresh.
/// </summary>
public sealed class CloudflareRefreshService : BackgroundService
{
    private readonly CloudflareIpRangeProvider _provider;
    private readonly IOptionsMonitor<CloudflareOptions> _options;
    private readonly ILogger<CloudflareRefreshService> _logger;

    /// <summary>Constructs the service.</summary>
    public CloudflareRefreshService(
        CloudflareIpRangeProvider provider,
        IOptionsMonitor<CloudflareOptions> options,
        ILogger<CloudflareRefreshService> logger)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _provider.RefreshAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            CloudflareLog.RefreshFailed(_logger, ex);
        }

        using var timer = new PeriodicTimer(_options.CurrentValue.RefreshInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await _provider.RefreshAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                CloudflareLog.RefreshFailed(_logger, ex);
            }
        }
    }
}
