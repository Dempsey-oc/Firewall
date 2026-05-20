using System.Linq;
using System.Net;
using Firewall.Networking;
using FluentAssertions;
using Xunit;

namespace Firewall.Core.Tests.Networking;

public sealed class CidrTrieTests
{
    [Fact]
    public void Empty_trie_contains_nothing()
    {
        var trie = new CidrTrie();
        trie.Contains(IPAddress.Parse("8.8.8.8")).Should().BeFalse();
        trie.Count.Should().Be(0);
    }

    [Fact]
    public void Single_v4_network_is_found()
    {
        var trie = new CidrTrie();
        trie.Add(Cidr.Parse("10.0.0.0/8"));
        trie.Build();

        trie.Contains(IPAddress.Parse("10.0.0.1")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("10.255.255.255")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("11.0.0.0")).Should().BeFalse();
    }

    [Fact]
    public void Multiple_v4_networks_are_found()
    {
        var trie = new CidrTrie();
        trie.AddRange(new[]
        {
            Cidr.Parse("10.0.0.0/8"),
            Cidr.Parse("192.168.0.0/16"),
            Cidr.Parse("172.16.0.0/12"),
        });
        trie.Build();

        trie.Contains(IPAddress.Parse("10.0.0.1")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("192.168.42.7")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("172.20.0.0")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("8.8.8.8")).Should().BeFalse();
    }

    [Fact]
    public void Ipv6_lookups_work()
    {
        var trie = new CidrTrie();
        trie.Add(Cidr.Parse("2001:db8::/32"));
        trie.Build();

        trie.Contains(IPAddress.Parse("2001:db8::1")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("2001:db9::1")).Should().BeFalse();
    }

    [Fact]
    public void Duplicate_adds_dont_inflate_count()
    {
        var trie = new CidrTrie();
        trie.Add(Cidr.Parse("10.0.0.0/8"));
        trie.Add(Cidr.Parse("10.0.0.0/8"));
        trie.Count.Should().Be(1);
    }

    [Fact]
    public void Mixed_family_does_not_match_across()
    {
        var trie = new CidrTrie();
        trie.Add(Cidr.Parse("10.0.0.0/8"));
        trie.Contains(IPAddress.Parse("::1")).Should().BeFalse();
    }

    [Fact]
    public void Large_dataset_returns_correct_results()
    {
        var trie = new CidrTrie();
        var nets = Enumerable.Range(0, 256)
            .Select(i => Cidr.Parse($"10.{i}.0.0/16"))
            .ToList();
        trie.AddRange(nets);
        trie.Build();

        trie.Count.Should().Be(256);
        trie.Contains(IPAddress.Parse("10.42.0.0")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("10.42.255.255")).Should().BeTrue();
        trie.Contains(IPAddress.Parse("11.0.0.0")).Should().BeFalse();
    }
}
