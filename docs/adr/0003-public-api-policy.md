# ADR 0003: Public API surface policy

* Status: Accepted
* Date: 2026-05-20

## Context

PR #1 introduced `PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt` files via
`Microsoft.CodeAnalysis.PublicApiAnalyzers`, but Phase 0–8 left
`RS0016/RS0017/RS0036/RS0037/RS0041` suppressed in `Directory.Build.props`'s
`NoWarn` list. The surface was effectively unfrozen — anyone could add or
remove a public symbol without a corresponding `PublicAPI.*.txt` edit, which
defeats the analyzer's whole purpose.

Phase 10 takes the analyzer live. With it live, we need a written policy so
maintainers don't fight the analyzer or game it.

## Decision

### What counts as "public API"

For every package whose `IsPackable == true` (all 10 src/ projects):

1. **In scope**: every type, member, constant, enum value, attribute,
   operator, conversion, and event whose effective accessibility is `public`
   or `protected` in a non-sealed type, declared in any namespace under
   `Firewall.*`.
2. **Out of scope**:
   - `internal` types and members (even those exposed via `InternalsVisibleTo`).
   - Types under `Firewall.Internal` (convention: utilities not promised to
     consumers; the namespace itself signals "do not depend on this").
   - Source-generated members (e.g. `[LoggerMessage]` partial implementations,
     records' compiler-generated `<Clone>$`). The analyzer auto-recognises
     these via attribute markers.

Anything in scope must appear in `PublicAPI.Shipped.txt` once shipped, and in
`PublicAPI.Unshipped.txt` between commits and the next release tag.

### Adding new API

1. Author the new public type or member.
2. Build the project. The analyzer emits `RS0016` with the exact line to add.
3. Paste the line into `PublicAPI.Unshipped.txt` (sorted lexicographically,
   keeping `#nullable enable` as the first line).
4. Commit both changes together. A diff that adds public surface without the
   matching analyzer-line is an immediate red flag in review.

### Removing or renaming API

1. Mark the symbol `[Obsolete]` (warning) for one major version.
2. After the deprecation window:
   - Move the entry from `PublicAPI.Shipped.txt` to
     `PublicAPI.Unshipped.txt` with a `*REMOVED*` prefix
     (`*REMOVED*Firewall.OldType`).
   - Delete the implementation.
3. The release that ships the removal must be a major-version bump per
   SemVer. ApiCompat (Phase 16) enforces this.

### Nullability changes

Treated as breaking: a `string!` return becoming `string?` is observable to
consumers via nullable diagnostics. Same as removal — deprecate first, then
edit the line.

### Re-publishing a previously removed name

Don't. Pick a new name to avoid the
[binding-redirect / type-forwarding hazard](https://learn.microsoft.com/dotnet/core/whats-new/dotnet-10) where a
consumer compiled against the old removed symbol resolves to the new (and
semantically different) one.

### Records and compiler-generated members

`record` and `record struct` declarations auto-generate `Equals`,
`GetHashCode`, `ToString`, `op_Equality`, `op_Inequality`, `<Clone>$`, and a
copy constructor. These all count as public API and must appear in
`PublicAPI.Shipped.txt`. Their entries look like:

```
override Firewall.TrustedProxyEntry.ToString() -> string!
Firewall.TrustedProxyEntry.Equals(Firewall.TrustedProxyEntry? other) -> bool
static Firewall.TrustedProxyEntry.operator ==(...) -> bool
~override Firewall.RuleEvaluation.ToString() -> string  ← record struct, nullable-oblivious
```

The `~` prefix marks nullable-oblivious annotations on record-struct overrides;
that's the analyzer's expected form, don't try to "fix" it to `string!`.

### The Firewall.Internal namespace

Anything in `Firewall.Internal.*` is by convention internal even when declared
`public`. We do this when the type must be visible across assembly boundaries
(via `InternalsVisibleTo` to test projects). Consumers who reference it bear
the breakage risk. ADRs and XML doc on those types should call this out.

### The Firewall meta-package surface

`Firewall.csproj` is the v3 compatibility shim plus a transitive re-export.
Its 268-entry shipped surface is mostly the `CountryCode` enum's 250
ISO 3166 values. The enum is fully shipped surface; **values must not be
removed** without a v5 major bump even if MaxMind's database drops or renames
a country.

## Consequences

### Positive

- Reviewers see the surface diff inline with the code diff. A PR that adds
  `MyNewClass.cs` but no `PublicAPI.Unshipped.txt` change is obviously
  wrong before any human reads the code.
- Nullability drift is caught at build time. We don't need a separate
  ApiCompat run for this case; the analyzer is sufficient.
- The surface is queryable: any tool can read `PublicAPI.Shipped.txt` and
  know exactly what's promised to consumers.

### Negative

- Friction on every public-surface change. Mitigated by:
  - `dotnet format analyzers --diagnostics RS0016 --severity error --fix`
    auto-generates entries in the IDE.
  - The CI step prints the missing lines verbatim — paste them in.
- Compiler-generated members for records have to be enumerated. This
  surprises first-time contributors; the ADR section above is the
  reference.

## Related

- ADR 0001 — multi-package architecture (defines what "the package" means).
- ADR 0002 — async rule contract (introduced the `IFirewallRule` shape that
  this ADR now freezes).
- `docs/migration-v3-to-v4.md` — what v3 surface stayed, what moved.
