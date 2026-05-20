using System;
using System.Net;
using System.Net.Sockets;
using Firewall.Internal;

namespace Firewall.Networking;

/// <summary>
/// An immutable CIDR network (address + prefix length).
/// </summary>
/// <remarks>
/// The address is normalised to the network address (host bits zeroed).
/// IPv4-mapped-to-IPv6 addresses are normalised to their IPv4 form.
/// </remarks>
public sealed class Cidr : IEquatable<Cidr>
{
    /// <summary>The network address (host bits zeroed).</summary>
    public IPAddress Address { get; }

    /// <summary>The prefix length (e.g. <c>24</c> for <c>10.0.0.0/24</c>).</summary>
    public int PrefixLength { get; }

    /// <summary>True if this network covers IPv4 addresses.</summary>
    public bool IsIPv4 { get; }

    private readonly byte[] _networkBytes;

    /// <summary>Reads-only view of the network address bytes.</summary>
    internal ReadOnlySpan<byte> NetworkBytes => _networkBytes;

    private Cidr(IPAddress address, int prefixLength, byte[] networkBytes, bool isIPv4)
    {
        Address = address;
        PrefixLength = prefixLength;
        _networkBytes = networkBytes;
        IsIPv4 = isIPv4;
    }

    /// <summary>Parses a CIDR string such as <c>10.0.0.0/8</c> or <c>2001:db8::/32</c>.</summary>
    public static Cidr Parse(string cidr)
    {
        Throw.IfNull(cidr);
        if (!TryParse(cidr, out var result))
            throw new FormatException($"Invalid CIDR notation: '{cidr}'.");
        return result;
    }

    /// <summary>Attempts to parse a CIDR string. Never throws.</summary>
    public static bool TryParse(string? cidr, out Cidr result)
    {
        result = null!;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var slash = cidr.IndexOf('/');
        if (slash < 0) return false;

#if NET8_0_OR_GREATER
        var addressPart = cidr.AsSpan(0, slash);
        var prefixPart = cidr.AsSpan(slash + 1);
#else
        var addressPart = cidr.Substring(0, slash);
        var prefixPart = cidr.Substring(slash + 1);
#endif

        if (!IPAddress.TryParse(addressPart, out var address)) return false;
        if (!int.TryParse(prefixPart, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var prefix)) return false;

        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        var isIPv4 = address.AddressFamily == AddressFamily.InterNetwork;
        var maxBits = isIPv4 ? 32 : 128;
        if (prefix < 0 || prefix > maxBits) return false;

        var bytes = address.GetAddressBytes();
        ApplyMask(bytes, prefix);

#if NET8_0_OR_GREATER
        var normalised = new IPAddress(bytes);
#else
        var normalised = new IPAddress(bytes);
#endif

        result = new Cidr(normalised, prefix, bytes, isIPv4);
        return true;
    }

    /// <summary>Returns true iff <paramref name="address"/> is contained within this network.</summary>
    public bool Contains(IPAddress address)
    {
        Throw.IfNull(address);
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        var queryIsIPv4 = address.AddressFamily == AddressFamily.InterNetwork;
        if (queryIsIPv4 != IsIPv4) return false;

#if NET8_0_OR_GREATER
        Span<byte> buf = stackalloc byte[16];
        if (!address.TryWriteBytes(buf, out var written)) return false;
        return ContainsCore(buf[..written]);
#else
        var bytes = address.GetAddressBytes();
        return ContainsCore(bytes);
#endif
    }

    internal bool ContainsCore(ReadOnlySpan<byte> addressBytes)
    {
        if (addressBytes.Length != _networkBytes.Length) return false;

        var fullBytes = PrefixLength >> 3;
        var remaining = PrefixLength & 7;

        for (var i = 0; i < fullBytes; i++)
            if (addressBytes[i] != _networkBytes[i]) return false;

        if (remaining == 0) return true;

        var mask = (byte)(0xFF << (8 - remaining));
        return (addressBytes[fullBytes] & mask) == (_networkBytes[fullBytes] & mask);
    }

    private static void ApplyMask(byte[] bytes, int prefix)
    {
        var fullBytes = prefix >> 3;
        var remaining = prefix & 7;

        for (var i = fullBytes + (remaining > 0 ? 1 : 0); i < bytes.Length; i++)
            bytes[i] = 0;

        if (remaining > 0)
        {
            var mask = (byte)(0xFF << (8 - remaining));
            bytes[fullBytes] &= mask;
        }
    }

    /// <inheritdoc/>
    public bool Equals(Cidr? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        if (PrefixLength != other.PrefixLength) return false;
        if (_networkBytes.Length != other._networkBytes.Length) return false;
        for (var i = 0; i < _networkBytes.Length; i++)
            if (_networkBytes[i] != other._networkBytes[i]) return false;
        return true;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Cidr c && Equals(c);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hc = new HashCode();
        hc.Add(PrefixLength);
        foreach (var b in _networkBytes) hc.Add(b);
        return hc.ToHashCode();
    }

    /// <inheritdoc/>
    public override string ToString() => $"{Address}/{PrefixLength}";

    /// <summary>Equality operator.</summary>
    public static bool operator ==(Cidr? left, Cidr? right) => left is null ? right is null : left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(Cidr? left, Cidr? right) => !(left == right);
}
