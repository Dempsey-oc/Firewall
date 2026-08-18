# Contributing to Firewall

Thanks for considering a contribution. If you read nothing else, read the
[PR checklist](#pr-checklist) at the bottom.

## Local dev setup

Required:
- .NET 10 SDK (`global.json` pins `10.0.100` with `latestFeature` roll-forward).
- Git.

Recommended:
- `dotnet tool install -g dotnet-reportgenerator-globaltool` for local coverage.
- `dotnet tool install -g dotnet-stryker` if you're working on `Firewall.Core`.

First-time:
```sh
git clone https://github.com/dempsey-oc/firewall.git
cd firewall
dotnet restore Firewall.sln
dotnet build Firewall.sln -c Release
dotnet test Firewall.sln -c Release
```

Same sequence CI runs. If it doesn't pass locally, it won't pass in CI.

## Repository layout

| Path | What lives here |
|---|---|
| `src/` | The 10 NuGet packages. Each one is an isolated csproj. |
| `tests/` | One `*.Tests/` per `src/` project, plus integration tests. |
| `bench/` | BenchmarkDotNet projects. |
| `samples/` | Reference apps showing common topologies. |
| `docs/` | ADRs, threat model, runbook, perf characteristics. |
| `.github/` | CI / Dependabot / issue templates. |

See [`docs/adr/0001-multi-package-architecture.md`](docs/adr/0001-multi-package-architecture.md)
for the rationale behind the package split.

## Branching

```
feat/<phase>-<short-slug>   # new behaviour, optionally tied to a roadmap phase
fix/<short-slug>            # bug fix
chore/<short-slug>          # repo plumbing
docs/<short-slug>           # docs only
```

Open PRs against `dev`, not `master`. `dev` periodically gets merged to
`master` for releases.

## Commits

We use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>)?: <subject>

<body explaining WHY, not WHAT>
```

| Type | When |
|---|---|
| `feat`     | New behaviour visible to a consumer. |
| `fix`      | Bug fix. |
| `perf`     | Performance change with benchmark evidence. |
| `refactor` | Internal restructuring, no behaviour change. |
| `test`     | Add or correct tests only. |
| `docs`     | Markdown / XML doc only. |
| `build`    | csproj, props/targets, NuGet metadata. |
| `ci`       | Anything under `.github/`. |
| `chore`    | Repo plumbing (dependabot, gitignore, version bump). |

Scope (optional) is the package name without `Firewall.` prefix: `core`,
`aspnetcore`, `cloudflare`, etc.

Subject rules:
- ≤ 70 characters, imperative present tense ("add", not "added").
- No trailing period.
- Lowercase after the colon unless a proper noun.

Body rules:
- Wrap at 72 columns.
- Explain **why** the change is needed and what's surprising. Don't restate
  the diff.
- Reference issues / PRs by `#<n>`, ADRs by path.

Every commit on a `dev`-targeted branch must compile and tests must pass on
its own. Use `git rebase -i` to fold WIP commits before opening the PR.

## Public API surface

This package uses `Microsoft.CodeAnalysis.PublicApiAnalyzers`. The 30-second
version, per [`docs/adr/0003-public-api-policy.md`](docs/adr/0003-public-api-policy.md):

- Adding a new public type or member? Build will fail with `RS0016` and
  print the exact line to add to `PublicAPI.Unshipped.txt`. Paste it in.
- Removing or renaming public API? `[Obsolete]` for one major version, then
  move the entry to `*REMOVED*Firewall.OldType` in Unshipped.
- Nullability change (`string!` → `string?`) is treated as breaking — same
  rules as removal.

## Tests

- Unit tests in `tests/Firewall.<Package>.Tests/`. xUnit + FluentAssertions.
- Integration tests in `tests/Firewall.AspNetCore.Tests/` use `TestHost`.
- Coverage threshold: 85% line coverage on `src/` (enforced in CI).
- Mutation score threshold: 70% on `Firewall.Core` (enforced in CI).

Run locally:
```sh
dotnet test Firewall.sln -c Release --collect:"XPlat Code Coverage" --settings coverlet.runsettings
reportgenerator -reports:'**/coverage.cobertura.xml' -targetdir:coverage -reporttypes:TextSummary
cat coverage/Summary.txt
```

## CHANGELOG

Every PR that changes behaviour adds an entry under `[Unreleased]` in
`CHANGELOG.md`. Sections: `Added`, `Changed`, `Removed`, `Fixed`, `Security`.

## Code style

- `.editorconfig` is checked in; ensure your editor reads it.
- `Nullable` is `enable` everywhere. No `#nullable disable`. If you need a
  null, use `?` in the type, not `!`-suppression.
- `TreatWarningsAsErrors` is on; analyzer findings fail the build.
- Avoid emojis in code, commits, and docs.

## PR checklist

Before requesting review:

- [ ] `dotnet build Firewall.sln -c Release` — 0 errors.
- [ ] `dotnet test Firewall.sln -c Release` — all green.
- [ ] One-green-build-per-commit (`git rebase -i` to fold WIPs).
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (if behaviour changed).
- [ ] `PublicAPI.Unshipped.txt` updated (if public surface changed).
- [ ] Linked ADR (if architectural).

## Reporting bugs

Security bugs: see [`SECURITY.md`](SECURITY.md) — do not file publicly.

Everything else: open an issue with the package + version, a minimal
reproducer (a failing test if you can, or a curl session), and expected vs.
actual behaviour.

## Code of Conduct

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
