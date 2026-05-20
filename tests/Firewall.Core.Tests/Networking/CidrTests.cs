using System.Net;
using Firewall.Networking;
using FluentAssertions;
using Xunit;

namespace Firewall.Core.Tests.Networking;

public sealed class CidrTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("192.168.0.0/16", "192.168.42.7", true)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("0.0.0.0/0", "203.0.113.1", true)]
    [InlineData("203.0.113.0/24", "203.0.113.255", true)]
    [InlineData("203.0.113.0/24", "203.0.114.0", false)]
    [InlineData("198.51.100.0/24", "198.51.100.0", true)]
    [InlineData("198.51.100.0/24", "198.51.99.255", false)]
    [InlineData("172.16.0.0/12", "172.31.255.255", true)]
    [InlineData("172.16.0.0/12", "172.32.0.0", false)]
    public void Contains_IPv4(string cidrString, string ipString, bool expected)
    {
        var cidr = Cidr.Parse(cidrString);
        cidr.Contains(IPAddress.Parse(ipString)).Should().Be(expected);
    }

    [Theory]
    [InlineData("2001:db8::/32", "2001:db8::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("::/0", "fe80::1", true)]
    [InlineData("fe80::/10", "fe80::abcd", true)]
    [InlineData("fe80::/10", "ff00::1", false)]
    public void Contains_IPv6(string cidrString, string ipString, bool expected)
    {
        var cidr = Cidr.Parse(cidrString);
        cidr.Contains(IPAddress.Parse(ipString)).Should().Be(expected);
    }

    [Fact]
    public void Mixed_family_returns_false()
    {
        var cidr = Cidr.Parse("10.0.0.0/8");
        cidr.Contains(IPAddress.Parse("::1")).Should().BeFalse();
    }

    [Fact]
    public void Mapped_ipv4_in_ipv6_is_normalised()
    {
        var cidr = Cidr.Parse("10.0.0.0/8");
        cidr.Contains(IPAddress.Parse("::ffff:10.0.0.1")).Should().BeTrue();
    }

    [Theory]
    [InlineData("not a cidr")]
    [InlineData("10.0.0.0")]
    [InlineData("10.0.0.0/33")]
    [InlineData("2001:db8::/129")]
    [InlineData("10.0.0.0/-1")]
    [InlineData(null)]
    [InlineData("")]
    public void TryParse_returns_false_for_garbage(string? input)
    {
        Cidr.TryParse(input, out _).Should().BeFalse();
    }

    [Fact]
    public void Parse_throws_for_invalid_input()
    {
        var act = () => Cidr.Parse("not a cidr");
        act.Should().Throw<System.FormatException>();
    }

    [Fact]
    public void ToString_round_trips()
    {
        Cidr.Parse("10.0.0.0/8").ToString().Should().Be("10.0.0.0/8");
        Cidr.Parse("2001:db8::/32").ToString().Should().Be("2001:db8::/32");
    }

    [Fact]
    public void Equality_works()
    {
        var a = Cidr.Parse("10.0.0.0/8");
        var b = Cidr.Parse("10.0.0.0/8");
        var c = Cidr.Parse("10.0.0.0/16");
        a.Equals(b).Should().BeTrue();
        a.Equals(c).Should().BeFalse();
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
        a.GetHashCode().Should().Be(b.GetHashCode());
    }

    [Fact]
    public void Normalises_host_bits_to_zero()
    {
        // /24 of 10.0.0.123 should be 10.0.0.0/24
        Cidr.Parse("10.0.0.123/24").ToString().Should().Be("10.0.0.0/24");
    }
}
