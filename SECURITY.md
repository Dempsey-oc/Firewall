# Security policy

## Supported versions

| Version | Supported? | Security updates until |
|---|---|---|
| 4.x   | ✅ | TBD (LTS aligned with .NET 10) |
| 3.x   | ⚠ Critical fixes only | 6 months after 4.0.0 GA |
| ≤ 2.x | ❌ | Out of support |

## Reporting a vulnerability

**Do not file a public GitHub issue, PR, or discussion for a security
report.** Public disclosure before a fix is available puts every consumer
of the package at risk.

Please report via GitHub's [private vulnerability reporting][gh-priv]:
https://github.com/dempsey-oc/firewall/security/advisories/new. Reports route
to the maintainers privately and acknowledgements go out within 3 working
days.

If GitHub's private reporting is unavailable, email `losloscripts@gmail.com`
with subject `[SECURITY] Firewall: <one-line summary>`.

Useful things to include:
- Affected package + version (e.g. `Firewall.Providers.Cloudflare 4.0.0`).
- A minimal repro: a failing test, an `appsettings.json`, or a shell session.
- The threat scenario you're worried about. We model against
  [`docs/security/threat-model.md`][tm] — pointing at a row helps triage.
- A suggested CVSS v3.1 vector if you have one (we'll recompute, but your
  read is useful signal).

[gh-priv]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
[tm]: docs/security/threat-model.md

## Triage timeline

| Severity (CVSS) | First triage | Fix landed in dev | Coordinated disclosure |
|---|---|---|---|
| Critical (9.0 – 10.0) | within 24 h | within 5 working days | + 7 days for downstream embargo |
| High (7.0 – 8.9) | within 3 working days | within 14 days | + 7 days |
| Medium (4.0 – 6.9) | within 5 working days | next minor release | with the release |
| Low (< 4.0) | within 10 working days | next minor release | with the release |

"Triage" = report acknowledged, assigned a severity, and either has a fix in
progress or is being declined with a written rationale.

## Coordinated disclosure

We follow [Project Zero–style 90-day disclosure][p0] with a small twist for
ecosystem-wide issues: if a fix lands on dev within the disclosure window, we
publish the advisory and CVE only after the fixed NuGet package is live on
nuget.org, so consumers can `dotnet add package` the fixed version the moment
they read the advisory.

[p0]: https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html

## Cryptographic verification

Every release of `Firewall.*` packages is:
- Signed with our author certificate, RFC 3161 timestamp from DigiCert's TSA.
- Attested to via SLSA L3 build provenance. Verify with:
  ```sh
  gh attestation verify Firewall.4.0.0.nupkg --owner dempsey-oc
  ```
- Built deterministically from a public commit SHA. The `reproducible-build`
  CI workflow rebuilds and byte-compares every nightly build.

## What this package is NOT

The Firewall package:
- is not a Web Application Firewall (WAF) — no payload inspection;
- is not a DDoS mitigation layer — it's an L3/L4 allow-list at app boundary;
- does not replace network-level firewalls in front of your hosts.

Out-of-scope reports:
- "I can DoS the package by sending 100k requests/second" — handled upstream
  by your reverse proxy / CDN / WAF.
- "The MaxMind database I supplied returns the wrong country for this IP" —
  that's a MaxMind issue.
- "ASP.NET Core middleware ordering means my X is hit before Firewall" —
  documented; middleware order is the application's call.

In-scope reports:
- Anything in `docs/security/threat-model.md` that we miss or model wrong;
- Bypasses of the `X-Forwarded-For` trusted-proxy walker;
- Information disclosure via metric tags / log payloads;
- Snapshot-corruption attacks against the Cloudflare / MaxMind providers;
- Anything that breaks the public API contract in a way that a consumer
  would consider unsafe.
