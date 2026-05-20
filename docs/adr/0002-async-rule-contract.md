# ADR 0002: Async, cancellable rule contract

* Status: Accepted
* Date: 2026-05-19

## Context

The v3 `IFirewallRule.IsAllowed(HttpContext) -> bool` contract locked every
implementation into synchronous evaluation. Rules that needed to consult
distributed caches, threat-intel APIs, or external geolocation services had to
either block on `.Result` (causing thread-pool starvation) or accept incomplete
information.

The Cloudflare integration in v3 demonstrated the same problem at startup:

```csharp
var (ips, cidrs) = helper.GetIPAddressRangesAsync(url1, url2).Result;
```

## Decision

The new contract is:

```csharp
public interface IFirewallRule
{
    string Name { get; }
    int Order { get; }
    ValueTask<RuleEvaluation> EvaluateAsync(FirewallContext context, CancellationToken ct);
}
```

Key points:

- `ValueTask` keeps the synchronous fast-path allocation-free.
- `CancellationToken` propagates through to network-bound rules so requests can
  abort on client disconnect or an engine-level timeout.
- `RuleEvaluation` explicitly returns `Continue` / `Allow` / `Deny` instead of
  using bool/exception for control flow.
- `Name` and `Order` are required so the pipeline is introspectable for
  diagnostics endpoints.

## Consequences

### Positive

- Rules can do I/O without forcing sync-over-async.
- The pipeline can apply a per-evaluation timeout via `cts.CancelAfter`.
- Diagnostics endpoints can list rule names and orders.
- The Continue verdict makes chain semantics explicit; chains no longer rely on
  positional convention.

### Negative

- Breaking change from v3. Mitigated by the `[Obsolete]`
  `FirewallRuleExtensions.IsAllowed(this IFirewallRule, HttpContext) -> bool`
  shim, which adapts old callers at the cost of one allocation per request.
