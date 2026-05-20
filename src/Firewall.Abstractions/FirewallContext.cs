using System;
using System.Net;
using Firewall.Internal;
using Microsoft.AspNetCore.Http;

namespace Firewall;

/// <summary>
/// The host-agnostic evaluation context passed to every <see cref="IFirewallRule"/>.
/// </summary>
/// <remarks>
/// Decoupled from <see cref="HttpContext"/> so the engine can be reused in
/// non-HTTP hosts (gRPC interceptors, YARP transforms, background workers).
/// </remarks>
public readonly struct FirewallContext : IEquatable<FirewallContext>
{
    /// <summary>The remote client's IP address as observed by the engine (post trusted-proxy resolution).</summary>
    public IPAddress RemoteIp { get; }

    /// <summary>The raw <c>X-Forwarded-For</c> header value or equivalent, if present. Never trusted directly.</summary>
    public string? ForwardedFor { get; }

    /// <summary>The two-letter ISO 3166 country code, if resolvable. Populated by geo providers.</summary>
    public string? CountryCode { get; }

    /// <summary>The request scheme (http / https / grpc / ws / ...).</summary>
    public string Scheme { get; }

    /// <summary>The request method (GET, POST, ...). Empty string for non-HTTP transports.</summary>
    public string Method { get; }

    /// <summary>The request path. <see cref="PathString.Empty"/> for non-HTTP transports.</summary>
    public PathString Path { get; }

    /// <summary>The request headers. May be a no-op collection for non-HTTP transports.</summary>
    public IHeaderDictionary Headers { get; }

    /// <summary>The request-scoped service provider for resolving providers, caches, etc.</summary>
    public IServiceProvider Services { get; }

    /// <summary>The underlying transport-specific object, if any. Use sparingly; introduces coupling.</summary>
    public object? Transport { get; }

    /// <summary>Constructs a new <see cref="FirewallContext"/>.</summary>
    public FirewallContext(
        IPAddress remoteIp,
        string? forwardedFor,
        string? countryCode,
        string scheme,
        string method,
        PathString path,
        IHeaderDictionary headers,
        IServiceProvider services,
        object? transport = null)
    {
        Throw.IfNull(remoteIp);
        Throw.IfNull(headers);
        Throw.IfNull(services);

        RemoteIp = remoteIp;
        ForwardedFor = forwardedFor;
        CountryCode = countryCode;
        Scheme = scheme ?? string.Empty;
        Method = method ?? string.Empty;
        Path = path;
        Headers = headers;
        Services = services;
        Transport = transport;
    }

    /// <summary>Returns a copy of this context with the resolved country code set.</summary>
    public FirewallContext WithCountry(string? countryCode)
        => new(RemoteIp, ForwardedFor, countryCode, Scheme, Method, Path, Headers, Services, Transport);

    /// <inheritdoc/>
    public bool Equals(FirewallContext other)
        => ReferenceEquals(RemoteIp, other.RemoteIp)
           && ForwardedFor == other.ForwardedFor
           && CountryCode == other.CountryCode
           && Scheme == other.Scheme
           && Method == other.Method
           && Path == other.Path
           && ReferenceEquals(Headers, other.Headers)
           && ReferenceEquals(Services, other.Services)
           && ReferenceEquals(Transport, other.Transport);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is FirewallContext c && Equals(c);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(RemoteIp, Scheme, Method, Path);

    /// <summary>Equality operator.</summary>
    public static bool operator ==(FirewallContext left, FirewallContext right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(FirewallContext left, FirewallContext right) => !left.Equals(right);
}
