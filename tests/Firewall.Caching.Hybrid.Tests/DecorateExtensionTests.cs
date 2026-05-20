using System;
using Firewall.Caching;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Firewall.Caching.Hybrid.Tests;

/// <summary>
/// Tests for the internal Decorate&lt;TService, TDecorator&gt; service-collection
/// extension. Verifies both factory-based and instance-based original
/// registrations are wrapped correctly, and that an attempt to decorate an
/// unregistered service surfaces a clear error.
/// </summary>
public sealed class DecorateExtensionTests
{
    [Fact]
    public void Decorates_factory_registration()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IGreeter>(_ => new Hello());
        HybridCacheBuilderExtensions.Decorate<IGreeter, Upper>(services);

        var sp = services.BuildServiceProvider();
        sp.GetRequiredService<IGreeter>().Greet().Should().Be("HELLO");
    }

    [Fact]
    public void Decorates_instance_registration()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IGreeter>(new Hello());
        HybridCacheBuilderExtensions.Decorate<IGreeter, Upper>(services);

        var sp = services.BuildServiceProvider();
        sp.GetRequiredService<IGreeter>().Greet().Should().Be("HELLO");
    }

    [Fact]
    public void Decorates_implementation_type_registration()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IGreeter, Hello>();
        HybridCacheBuilderExtensions.Decorate<IGreeter, Upper>(services);

        var sp = services.BuildServiceProvider();
        sp.GetRequiredService<IGreeter>().Greet().Should().Be("HELLO");
    }

    [Fact]
    public void Throws_when_no_registration_to_decorate()
    {
        var services = new ServiceCollection();
        var act = () => HybridCacheBuilderExtensions.Decorate<IGreeter, Upper>(services);
        act.Should().Throw<InvalidOperationException>().WithMessage("*IGreeter*");
    }

    public interface IGreeter { string Greet(); }
    public sealed class Hello : IGreeter { public string Greet() => "hello"; }
    public sealed class Upper : IGreeter
    {
        private readonly IGreeter _inner;
        public Upper(IGreeter inner) { _inner = inner; }
        public string Greet() => _inner.Greet().ToUpperInvariant();
    }
}
