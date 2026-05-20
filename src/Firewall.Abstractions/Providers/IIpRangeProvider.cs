using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Firewall.Internal;
using Microsoft.Extensions.Primitives;

namespace Firewall.Providers;

/// <summary>
/// Supplies IP / CIDR allow- or block-lists, typically from a remote source
/// (Cloudflare, AWS WAF IPSet, threat-intel feed, etc.).
/// </summary>
public interface IIpRangeProvider
{
    /// <summary>A stable, log-safe identifier (e.g. <c>"cloudflare"</c>, <c>"aws-waf"</c>).</summary>
    string Name { get; }

    /// <summary>The current snapshot. Never null. Lock-free read; returns the most recently published value.</summary>
    IpRangeSnapshot Current { get; }

    /// <summary>Triggers an out-of-band refresh. Used by the hosted background service and by tests.</summary>
    ValueTask RefreshAsync(CancellationToken cancellationToken);

    /// <summary>A change token that fires when a new snapshot is published.</summary>
    IChangeToken WatchToken { get; }
}

/// <summary>
/// An immutable point-in-time view of a provider's range data.
/// </summary>
public sealed class IpRangeSnapshot
{
    /// <summary>An empty snapshot; safe sentinel for first-use before any refresh has succeeded.</summary>
    public static IpRangeSnapshot Empty { get; } = new(
        ipAddresses: Array.Empty<IPAddress>(),
        cidrs: Array.Empty<string>(),
        fetchedAtUtc: DateTimeOffset.MinValue,
        etag: null);

    /// <summary>The discrete IP addresses in this snapshot.</summary>
    public IReadOnlyList<IPAddress> IPAddresses { get; }

    /// <summary>The CIDR notations in this snapshot, in raw <c>address/bits</c> form.</summary>
    public IReadOnlyList<string> Cidrs { get; }

    /// <summary>When this snapshot was successfully retrieved.</summary>
    public DateTimeOffset FetchedAtUtc { get; }

    /// <summary>The upstream ETag, if the source provided one. Used to short-circuit unchanged refreshes.</summary>
    public string? Etag { get; }

    /// <summary>Constructs a new <see cref="IpRangeSnapshot"/>.</summary>
    public IpRangeSnapshot(
        IReadOnlyList<IPAddress> ipAddresses,
        IReadOnlyList<string> cidrs,
        DateTimeOffset fetchedAtUtc,
        string? etag)
    {
        Throw.IfNull(ipAddresses);
        Throw.IfNull(cidrs);
        IPAddresses = ipAddresses;
        Cidrs = cidrs;
        FetchedAtUtc = fetchedAtUtc;
        Etag = etag;
    }
}
