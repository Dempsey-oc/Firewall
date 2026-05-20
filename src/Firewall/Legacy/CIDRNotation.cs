using System;
using System.Net;
using Firewall.Networking;

namespace Firewall;

/// <summary>v3 compatibility shim. Prefer <see cref="Cidr"/> in <c>Firewall.Networking</c>.</summary>
[Obsolete("Use Firewall.Networking.Cidr. CIDRNotation will be removed in v5.")]
public sealed class CIDRNotation
{
    private readonly Cidr _inner;

    /// <summary>The network address.</summary>
    public IPAddress Address => _inner.Address;

    /// <summary>The prefix mask bit-count.</summary>
    public int MaskBits => _inner.PrefixLength;

    private CIDRNotation(Cidr inner) => _inner = inner;

    /// <summary>Parses a CIDR string like <c>10.0.0.0/8</c>.</summary>
    public static CIDRNotation Parse(string cidrNotation) => new(Cidr.Parse(cidrNotation));

    /// <summary>True iff the given address is in this network.</summary>
    public bool Contains(IPAddress address) => _inner.Contains(address);

    /// <inheritdoc/>
    public override string ToString() => _inner.ToString();

    /// <summary>Implicit conversion to the modern <see cref="Cidr"/>.</summary>
    public static implicit operator Cidr(CIDRNotation cidr) => cidr._inner;
}
