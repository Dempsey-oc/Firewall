# ADR 0001: Split the monolithic Firewall package into a multi-package architecture

* Status: Accepted
* Date: 2026-05-19

## Context

Through v3, `Firewall` was a single NuGet package that bundled:

- The engine and built-in rules.
- ASP.NET Core middleware glue.
- Cloudflare integration via a synchronous HTTP fetch at startup.
- An embedded MaxMind GeoLite2 database.

This produced four classes of problem for enterprise consumers:

1. **Forced dependencies**. Anyone using the package paid for MaxMind, the embedded
   geo database, and `HttpClient` regardless of which rules they actually used.
2. **Licensing surface**. The embedded GeoLite2 database is redistributed under
   MaxMind's licence, which is non-trivial to vet at scale.
3. **Coupled release cadence**. Any change to Cloudflare URL parsing forced a full
   `Firewall` release. Providers should evolve independently of the engine.
4. **Restricted hosting**. The engine was bound to `HttpContext`, so reuse in
   YARP transforms or gRPC interceptors required forking the code.

## Decision

Split into ten packages along strong axes:

| Package | Depends on | Purpose |
|---|---|---|
| `Firewall.Abstractions` | (none) | Contracts only — interfaces, options records, no engine code. |
| `Firewall.Core` | Abstractions | Engine, Patricia-trie CIDR matcher, built-in rules. |
| `Firewall.AspNetCore` | Core + ASP.NET Core framework reference | Middleware + DI builder. |
| `Firewall.Providers.Cloudflare` | AspNetCore | Background-refresh provider. |
| `Firewall.Geo.MaxMind` | AspNetCore | External geo provider. |
| `Firewall.OpenTelemetry` | AspNetCore | Telemetry adapter. |
| `Firewall.HealthChecks` | AspNetCore | Health check integration. |
| `Firewall.Caching.Hybrid` | AspNetCore | HybridCache decorator. |
| `Firewall.Yarp` | AspNetCore | YARP transform. |
| `Firewall` | All of the above | v3 compatibility shim + meta-package. |

## Consequences

### Positive

- Consumers pay only for what they use.
- `Firewall.Abstractions` is AOT/trim-friendly and dependency-free, suitable for
  use in libraries that ship their own rule implementations.
- The engine is now host-agnostic — `FirewallContext` is a struct, not an
  `HttpContext`, so it works in YARP, gRPC, Orleans, and background workers.
- Providers can release on their own cadence.
- Licensed data (MaxMind) is no longer redistributed by the package.

### Negative

- Ten packages to publish instead of one. Mitigated by `Firewall` meta-package
  and a release script that publishes them atomically.
- Slightly more configuration code at call sites. Mitigated by the fluent
  `IFirewallBuilder` extensions.
