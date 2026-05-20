# Migrating from Firewall v3 to v4

The v4 release is a ground-up rewrite. The v3 API is kept as `[Obsolete]` shims
so existing code continues to compile, but every consumer should plan a migration
because:

- v3 blocked on async at startup (`.Result` in `ExceptFromCloudflare()`).
- v3 targeted net5.0 (EOL since May 2022).
- v3 embedded the MaxMind GeoLite2 database, which goes stale at package time
  and carries licensing exposure.
- v3 had no `IOptions<T>`, no telemetry, no health checks, and no caching.

## TL;DR

```diff
- using Firewall;
+ using Firewall;
+ using Firewall.DependencyInjection;
+ using Firewall.Providers.Cloudflare;
+ using Firewall.Geo.MaxMind;

- public void Configure(IApplicationBuilder app)
- {
-     app.UseFirewall(
-         FirewallRulesEngine
-             .DenyAllAccess()
-             .ExceptFromCountries(new[] { CountryCode.GB })
-             .ExceptFromIPAddresses(allowedIps)
-             .ExceptFromCloudflare()
-             .ExceptFromLocalhost());
- }
+ public void ConfigureServices(IServiceCollection services)
+ {
+     services.AddFirewall()
+         .BindConfiguration(Configuration)
+         .AddCloudflareProvider()
+         .AddMaxMindGeo(o => o.DatabasePath = "/var/lib/geoip/GeoLite2-Country.mmdb")
+         .AddOpenTelemetry()
+         .AddHealthCheck();
+ }
+
+ public void Configure(IApplicationBuilder app)
+ {
+     app.UseForwardedHeaders();
+     app.UseFirewall();
+ }
```

`appsettings.json`:

```json
{
  "Firewall": {
    "Rules": {
      "DefaultDeny": true,
      "AllowLocalhost": true,
      "AllowedIps": [ "10.20.30.40" ],
      "AllowedCidrs": [ "110.40.88.0/28" ],
      "AllowedCountries": [ "GB" ]
    },
    "TrustedProxies": {
      "KnownNetworks": [ "10.0.0.0/8" ],
      "ForwardLimit": 2
    }
  }
}
```

## API mapping

| v3 | v4 |
|---|---|
| `FirewallRulesEngine.DenyAllAccess()` | `FirewallOptions.Rules.DefaultDeny = true` |
| `.ExceptFromLocalhost()` | `Rules.AllowLocalhost = true` |
| `.ExceptFromIPAddresses(ips)` | `Rules.AllowedIps = [...]` |
| `.ExceptFromIPAddressRanges(cidrs)` | `Rules.AllowedCidrs = [...]` |
| `.ExceptFromCountries([CountryCode.X])` | `Rules.AllowedCountries = ["X"]` + `AddMaxMindGeo(...)` |
| `.ExceptFromCloudflare()` | `AddCloudflareProvider()` |
| `.ExceptWhen(predicate)` | Implement `IFirewallRule` or use `CustomRule` |
| `CIDRNotation.Parse(s)` | `Cidr.Parse(s)` |
| `CountryCode.GB` | `"GB"` (string) |
| `app.UseFirewall(rule, deniedDelegate)` | Configure `FirewallOptions.OnDeny`, use `app.UseFirewall()` |
| `IFirewallRule.IsAllowed(ctx)` | `IFirewallRule.EvaluateAsync(ctx, ct)` |

## Breaking changes

1. **`ExceptFromCloudflare()` is removed** (throws if called). The startup
   sync-over-async pattern is incompatible with our async-everywhere model.
   Use `AddCloudflareProvider()` instead.

2. **`ExceptFromCountries(CountryCode[])` is removed** (throws if called). The
   embedded MaxMind database is gone. Bind `AllowedCountries` (string codes) and
   register `AddMaxMindGeo()`.

3. **`IFirewallRule.IsAllowed(HttpContext)` is now an `[Obsolete]` extension**
   that adapts to the async API. Custom rules must implement the new contract.

4. **net5.0 is no longer supported**. The package targets `net10.0`.

## What's new

- **Telemetry**: `services.AddFirewall().AddOpenTelemetry()` registers an
  `ActivitySource` and `Meter` named `"Firewall"`.
- **Health checks**: `services.AddFirewall().AddHealthCheck()` reports degraded
  if any provider snapshot is older than `2 × ProviderRefreshInterval`.
- **HybridCache**: `services.AddFirewall().AddHybridCache()` caches geo lookups
  across instances when a distributed cache is configured.
- **YARP integration**: `services.AddFirewall().AddYarpIntegration()` adds a
  transform to every YARP route.
- **Health response controls**: `OnDeny` lets you set status code, body,
  content-type, and `Retry-After`.
- **Per-evaluation timeout**: A slow rule no longer hangs the pipeline.
