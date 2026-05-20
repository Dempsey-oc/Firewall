using Firewall;
using Firewall.DependencyInjection;
using Firewall.HealthChecks;
using Firewall.OpenTelemetry;
using Firewall.Providers.Cloudflare;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 2;
});

builder.Services
    .AddFirewall()
    .BindConfiguration(builder.Configuration)
    .AddCloudflareProvider()
    .AddOpenTelemetry()
    .AddHealthCheck();

var app = builder.Build();

app.UseForwardedHeaders();
app.UseFirewall();

app.MapHealthChecks("/healthz");
app.MapGet("/", () => "Hello from a properly firewalled v4 endpoint.");

app.Run();
