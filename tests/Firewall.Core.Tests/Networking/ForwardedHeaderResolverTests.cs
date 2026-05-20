using System.Net;
using Firewall.Networking;
using FluentAssertions;
using Xunit;

namespace Firewall.Core.Tests.Networking;

public sealed class ForwardedHeaderResolverTests
{
    [Fact]
    public void Without_xff_returns_peer()
    {
        var r = new ForwardedHeaderResolver(
            knownProxies: new[] { IPAddress.Parse("10.0.0.1") },
            knownNetworks: System.Array.Empty<Cidr>(),
            forwardLimit: 1);

        r.Resolve(IPAddress.Parse("10.0.0.1"), forwardedFor: null)
            .Should().Be(IPAddress.Parse("10.0.0.1"));
    }

    [Fact]
    public void Untrusted_peer_xff_is_ignored()
    {
        var r = new ForwardedHeaderResolver(
            knownProxies: new[] { IPAddress.Parse("10.0.0.1") },
            knownNetworks: System.Array.Empty<Cidr>(),
            forwardLimit: 5);

        // Peer 8.8.8.8 is not a trusted proxy → XFF is ignored.
        r.Resolve(IPAddress.Parse("8.8.8.8"), "1.2.3.4")
            .Should().Be(IPAddress.Parse("8.8.8.8"));
    }

    [Fact]
    public void Trusted_peer_xff_unwraps_one_hop()
    {
        var r = new ForwardedHeaderResolver(
            knownProxies: new[] { IPAddress.Parse("10.0.0.1") },
            knownNetworks: System.Array.Empty<Cidr>(),
            forwardLimit: 1);

        r.Resolve(IPAddress.Parse("10.0.0.1"), "1.2.3.4")
            .Should().Be(IPAddress.Parse("1.2.3.4"));
    }

    [Fact]
    public void Forward_limit_stops_walk()
    {
        var r = new ForwardedHeaderResolver(
            knownProxies: new[] { IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.0.0.2") },
            knownNetworks: System.Array.Empty<Cidr>(),
            forwardLimit: 1);

        // XFF has 2 hops, but we only walk back 1 → returns 10.0.0.2 (the previous proxy).
        r.Resolve(IPAddress.Parse("10.0.0.1"), "1.2.3.4, 10.0.0.2")
            .Should().Be(IPAddress.Parse("10.0.0.2"));
    }

    [Fact]
    public void Known_network_treated_as_trusted()
    {
        var r = new ForwardedHeaderResolver(
            knownProxies: System.Array.Empty<IPAddress>(),
            knownNetworks: new[] { Cidr.Parse("10.0.0.0/8") },
            forwardLimit: 1);

        r.Resolve(IPAddress.Parse("10.42.0.1"), "1.2.3.4")
            .Should().Be(IPAddress.Parse("1.2.3.4"));
    }
}
