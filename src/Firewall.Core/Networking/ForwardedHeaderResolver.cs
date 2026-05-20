using System;
using System.Collections.Generic;
using System.Net;
using Firewall.Internal;

namespace Firewall.Networking;

/// <summary>
/// Resolves the originating client IP from <c>X-Forwarded-For</c>, walking back
/// only through trusted proxies. Mirrors ASP.NET Core's ForwardedHeadersMiddleware
/// model, but as a pure function so the engine remains testable in isolation.
/// </summary>
public sealed class ForwardedHeaderResolver
{
    private readonly HashSet<IPAddress> _knownProxies;
    private readonly CidrTrie _knownNetworks;
    private readonly int _forwardLimit;

    /// <summary>Constructs a new resolver over the supplied trusted proxy configuration.</summary>
    public ForwardedHeaderResolver(IEnumerable<IPAddress> knownProxies, IEnumerable<Cidr> knownNetworks, int forwardLimit)
    {
        Throw.IfNull(knownProxies);
        Throw.IfNull(knownNetworks);

        _knownProxies = new HashSet<IPAddress>(knownProxies);
        _knownNetworks = new CidrTrie();
        foreach (var n in knownNetworks) _knownNetworks.Add(n);
        _knownNetworks.Build();
        _forwardLimit = forwardLimit < 0 ? 0 : forwardLimit;
    }

    /// <summary>
    /// Resolves the effective client IP given the socket peer and the comma-separated <c>X-Forwarded-For</c> header.
    /// </summary>
    /// <param name="peerAddress">The TCP peer that connected to this server.</param>
    /// <param name="forwardedFor">The <c>X-Forwarded-For</c> header value or <see langword="null"/>.</param>
    /// <returns>The resolved client IP, never null.</returns>
    public IPAddress Resolve(IPAddress peerAddress, string? forwardedFor)
    {
        Throw.IfNull(peerAddress);

        if (string.IsNullOrEmpty(forwardedFor)) return peerAddress;
        if (_forwardLimit <= 0) return peerAddress;
        if (!IsTrusted(peerAddress)) return peerAddress;

        var entries = forwardedFor!.Split(',');
        var current = peerAddress;
        var hops = 0;

        for (var i = entries.Length - 1; i >= 0 && hops < _forwardLimit; i--)
        {
            var token = entries[i].Trim();
            if (token.Length == 0) continue;
            if (!IPAddress.TryParse(token, out var parsed)) break;

            if (!IsTrusted(current))
                return current;

            current = parsed;
            hops++;
        }

        return current;
    }

    private bool IsTrusted(IPAddress address)
    {
        if (_knownProxies.Contains(address)) return true;
        if (_knownNetworks.Contains(address)) return true;
        return false;
    }
}
