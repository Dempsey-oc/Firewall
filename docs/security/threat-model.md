# Firewall — Threat Model

This document follows [STRIDE](https://en.wikipedia.org/wiki/STRIDE_model) per
component. Each row describes a threat, the affected component, and the
mitigation shipped with the package.

| # | Category | Threat | Component | Mitigation |
|---|---|---|---|---|
| 1 | **Spoofing** | Attacker forges `X-Forwarded-For` to impersonate a trusted IP and bypass rules. | `FirewallMiddleware` | `ForwardedHeaderResolver` walks the XFF chain only through explicitly configured `KnownProxies` / `KnownNetworks` and stops at `ForwardLimit`. Untrusted peers' XFF is ignored entirely. |
| 2 | **Spoofing** | Attacker masquerades as Cloudflare by sourcing requests from a recycled IP that's no longer in the Cloudflare range. | `CloudflareIpRangeProvider` | Snapshot is refreshed every `RefreshInterval` (default 6h) from `cloudflare.com/ips-v{4,6}` over TLS. |
| 3 | **Tampering** | An operator misconfigures CIDRs (`10.0.0.0/40`) and the engine silently accepts garbage. | `Cidr.Parse`, `FirewallOptionsValidator` | Strict parsing rejects invalid prefix lengths; `IValidateOptions` runs `ValidateOnStart`. |
| 4 | **Tampering** | An attacker poisons the geo database file on disk. | `MaxMindGeoProvider` | DB is opened read-only with `FileAccessMode.MemoryMapped`. Operators are responsible for delivery integrity (signed manifests, checksum verification — see deployment runbook). |
| 5 | **Repudiation** | Denied request can't be correlated to a rule. | `FirewallPipeline` | Every deny emits a structured log with `RuleName`, `Reason`, hashed remote IP (if configured) and an Activity span. |
| 6 | **Information disclosure** | Logged IPs constitute PII under GDPR / UK GDPR. | `FirewallOptions.HashIpsInTelemetry`, `FirewallTelemetry` | When `HashIpsInTelemetry=true`, IPs are HMAC-SHA256-hashed before being recorded. |
| 7 | **Information disclosure** | Deny response body leaks server identity or rule details. | `BlockResponseOptions` | Default body is empty. Body, status code, and content type are configurable; we recommend an empty body in production. |
| 8 | **DoS** | A slow rule (e.g. an external threat-intel call) blocks the pipeline. | `FirewallMiddleware`, `EvaluationTimeout` | A per-evaluation `CancellationTokenSource` with a configurable timeout (default 250ms) aborts slow rules. The middleware fail-closes on timeout. |
| 9 | **DoS** | A Cloudflare outage breaks all admit decisions for traffic relying on the provider. | `ProviderFailurePolicy` | Default `UseLastKnownGood` means a failed refresh does not invalidate the snapshot; the snapshot is only replaced when a new one arrives successfully. `FailClosed` and `FailOpen` are explicit alternatives. |
| 10 | **DoS** | Pathological CIDR list (10k+ entries) causes O(N) scans per request. | `CidrTrie` | Patricia trie provides O(W) lookups where W ≤ 128 bits. Benchmark gate in CI enforces a per-evaluation p99 budget. |
| 11 | **Elevation of privilege** | Middleware is registered after authorization — attackers who reach AuthZ never hit the firewall. | Documentation | Middleware order is documented in the README. The `UseFirewall()` extension is intentionally `IApplicationBuilder`-typed so it's placed by the developer; we do not auto-insert. |
| 12 | **Supply chain** | A malicious package update flows in via dependency hijack. | `Directory.Packages.props` + CI | Central package management, package-lock files in CI (`--locked-mode`), CodeQL scanning, SLSA L3 provenance attestation on every release. |
| 13 | **Supply chain** | The published nupkg differs from the tagged source. | `ContinuousIntegrationBuild=true`, `Deterministic=true` | Deterministic builds are reproducible from a tag; SourceLink embeds the source commit. |

## Out of scope

- L4 DDoS protection (handled upstream by Cloudflare / AWS Shield / Azure Front Door).
- WAF-style payload inspection. The package is an IP/geo/CIDR allow-list, not a WAF.
- Authentication or authorisation. Firewall runs **before** identity is established.
