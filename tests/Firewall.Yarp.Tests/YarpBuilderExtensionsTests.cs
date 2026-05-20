using Firewall.DependencyInjection;
using Firewall.Yarp;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Firewall.Yarp.Tests;

public sealed class YarpBuilderExtensionsTests
{
    [Fact]
    public void AddYarpIntegration_registers_a_transform_provider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFirewall();
        services.AddSingleton<FirewallTransform>();
        services.AddFirewall().AddYarpIntegration();

        services.Should().Contain(d => d.ServiceType == typeof(ITransformProvider));
    }
}
