# Changelog

All notable changes to the Firewall package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] — unreleased

### Architectural reset

This is a ground-up rewrite to bring the package up to current enterprise standards.
The v3 public surface (`FirewallRulesEngine`, `CIDRNotation`, `CountryCode`,
`UseFirewall(rule)`) is retained as `[Obsolete]` shims, but new code should use
the new async, options-driven, DI-first API.

### Added

- **Multi-package architecture**:
  - `Firewall.Abstractions` — contracts only, AOT/trim-friendly, no engine.
  - `Firewall.Core` — engine, Patricia-trie CIDR matcher, options validation, built-in rules.
  - `Firewall.AspNetCore` — middleware + `IFirewallBuilder` DI surface.
  - `Firewall.Providers.Cloudflare` — background refresh service with Polly resilience.
  - `Firewall.Geo.MaxMind` — out-of-band MaxMind .mmdb support (no embedded DB).
  - `Firewall.OpenTelemetry` — `ActivitySource` + `Meter` instrumentation.
  - `Firewall.HealthChecks` — `IHealthCheck` reporting on provider freshness.
  - `Firewall.Caching.Hybrid` — `HybridCache` decorator for geo lookups.
  - `Firewall.Yarp` — YARP reverse proxy transform.
  - `Firewall` — meta-package + v3 compatibility shims.
- **Async rule contract** with `ValueTask<RuleEvaluation>` and `CancellationToken`.
- **Patricia-trie CIDR matcher** — O(W) lookups, scales to 10k+ rules.
- **`X-Forwarded-For` trusted-proxy walker** — no more blind XFF trust.
- **Options pattern** with `IOptions<FirewallOptions>`, `IValidateOptions`, and `ValidateOnStart`.
- **OpenTelemetry instrumentation** — meter `Firewall`, activity source `Firewall`.
- **Source-generated logging** via `[LoggerMessage]` (zero allocation).
- **Native AOT and trim compatibility** for `Firewall.Abstractions` and `Firewall.Core`.
- **BenchmarkDotNet** project gating performance regressions.
- **Deterministic builds**, SourceLink, public-API analyzer, package validation.
- **CI workflow** with CodeQL, SBOM provenance attestation, AOT publish smoke.

### Changed

- Minimum framework is now **net10.0** (previously net5.0, EOL since 2022).
- `IFirewallRule.IsAllowed(HttpContext)` is now an `[Obsolete]` extension method
  delegating to the async `EvaluateAsync` API.

### Removed

- **Embedded MaxMind GeoLite2 DB**. Consumers must supply the database out-of-band
  (sidecar, init container, cron job). This removes licensing exposure and prevents
  the database from going stale at package time.
- **Sync-over-async Cloudflare bootstrap** (`.Result` in startup) — replaced by
  the hosted background service `CloudflareRefreshService`.

### Migration from v3

See `docs/migration-v3-to-v4.md`.
