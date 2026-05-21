# New Built-in Modules — Assessment

_Snapshot: refreshed during the Rust port. Companion to GAPS.md._

This document audits the current built-in CopilotModule catalog and proposes
the next batch of modules to ship. The goal is to fill **real product gaps**
that operators expect from a security platform but Kuzushi currently lacks.

## What ships today

| ID | Category | Entry point | Notes |
|----|----------|-------------|-------|
| `sast` | defense | Rust native module registry | Umbrella task runner |
| `secret-scan` / `license-scan` / `sbom-scan` / `iac-scan` / `dep-hygiene` / `cargo-audit` / `semgrep` / `codeql` | defense / governance | Rust native scanner modules | Deterministic scanner family |
| `agentic-sast` / `taint-iris` / `taint-iris-next` / `offense-review` / `systems-hunt` / `triage` / `verify` / `patch` / `findings` / `context` / `pipeline` | defense | Rust native modules and adapters | The SAST family |
| `recon` / `shinsa` / `prompt-armor` / `variant` / `ndiff` | intel / governance / offense | Rust native adapters | Deferred or exact-invocation surfaces where appropriate |

## Gaps

Cross-checking against what operators expect from a security pipeline:

1. **SBOM depth is still first-party inventory.** `sbom-scan` now extracts
   npm, Bower, Cargo, Python, Go, Composer, RubyGems, Maven/Gradle/SBT, NuGet, Dart, Conda, R, Helm, Elm, Julia, Conan, vcpkg, CPAN, opam, Hackage, Crystal, Haxelib, Nimble, Hex/Gleam/Mix, and Deno JSR import dependencies from package
   manifests including Cargo workspace and target-specific dependencies,
   PEP 621, PEP 735 dependency groups, and Poetry pyproject metadata,
   `requirements.txt` / `*-requirements.txt` files, Pipfile manifests,
   Conda environment files, R `DESCRIPTION` files, Helm `Chart.yaml`, Elm `elm.json`, Julia `Project.toml`, Conan `conanfile.txt`, vcpkg `vcpkg.json`, Perl `cpanfile`, OCaml `.opam` files, Haskell `.cabal` files, Crystal `shard.yml`, `bower.json`, `haxelib.json`, Nim `.nimble` files, `gleam.toml`, `mix.exs`, `deno.json`, `import_map.json`, `go.mod`,
   `composer.json`, `Gemfile`, `pom.xml`, Gradle `build.gradle` / `build.gradle.kts`, SBT `build.sbt`, .NET project PackageReference entries, and `pubspec.yaml` dependencies with package URL metadata, lockfile SHA-256
   digests including Bun `bun.lock` / `bun.lockb`, Bun `bun.lock` root and package dependency edges, npm package-lock v1/v2/v3, package.json root dependency edges, Cargo.toml root dependency edges including workspace and target scopes, Python pyproject and requirements root dependency edges, go.mod root dependency edges, composer.json root dependency edges, Gemfile root dependency edges, and pubspec.yaml root dependency edges,
   yarn.lock dependency and optional dependency edges, pnpm-lock importer and package dependency edges, Poetry lock
   dependency edges, Pipfile and Pipfile.lock root dependency edges, uv.lock package inventory and dependency edges,
   composer.lock package inventory and dependency edges, Gemfile.lock package inventory and dependency edges, NuGet packages.lock.json
   dependency edges, Swift Package.resolved root dependency edges, CocoaPods
   Podfile.lock root dependency edges, Carthage Cartfile.resolved root dependency edges,
   Bower bower.json root dependency edges, Haxelib haxelib.json root dependency edges, Nimble nimble file root dependency edges, Gleam gleam.toml and Mix mix.exs root dependency edges, Deno deno.json/import_map.json npm/JSR import, local `importMap` reference, and scoped-import root dependency edges, deno.lock npm/JSR package inventory and dependency edges, Helm Chart.yaml and Chart.lock root dependency edges, Elm elm.json direct dependency edges, Julia Project.toml root dependency edges, Conan conanfile.txt root dependency edges, vcpkg vcpkg.json root dependency edges, CPAN cpanfile root dependency edges, opam file root dependency edges, Cabal file root dependency edges, Crystal shard.yml root dependency edges, Gradle
   lockfile root dependency edges, Dart pubspec.lock direct dependency edges,
   Conda environment root dependency edges, R DESCRIPTION root edges and renv.lock package inventory and dependency edges, conservative go.sum
   root module edges, Maven pom.xml, Gradle build-file, and SBT build.sbt root dependency edges, NuGet project root dependency edges, and CycloneDX/SPDX JSON projections.
   Multi-ecosystem transitive graph
   enrichment remains future depth work; current lockfile graph extraction
   covers npm package-lock v1/v2/v3/v3 and shrinkwrap edges, Bun `bun.lock` root and package dependency edges, yarn.lock dependency and optional dependency
   edges, pnpm-lock importer and package dependency edges, Cargo.lock package dependency
   edges, Poetry lock dependency edges, Pipfile and Pipfile.lock root dependency edges, uv.lock package inventory
   edges, composer.lock package inventory and dependency edges, Gemfile.lock package inventory and dependency edges, NuGet
   packages.lock.json dependency edges, Swift Package.resolved root dependency
   edges, CocoaPods Podfile.lock root and pod dependency edges, Carthage
   Cartfile.resolved root dependency edges, Helm Chart.yaml and Chart.lock root
   dependency edges, Bower bower.json root dependency edges, Haxelib haxelib.json root dependency edges, Nimble nimble file root dependency edges, Gleam gleam.toml and Mix mix.exs root dependency edges, Deno deno.json/import_map.json npm/JSR import, local `importMap` reference, and scoped-import root dependency edges, deno.lock npm/JSR package inventory and dependency edges, Elm elm.json direct dependency edges, Julia Project.toml root dependency edges, Conan conanfile.txt root dependency edges, vcpkg vcpkg.json root dependency edges, CPAN cpanfile root dependency edges, opam file root dependency edges, Cabal file root dependency edges, Crystal shard.yml root dependency edges, Gradle lockfile root dependency edges, Mix mix.lock package dependency edges, Dart pubspec.lock direct
   dependency edges, Conda environment root dependency edges, R DESCRIPTION root
   edges and renv.lock package inventory and dependency edges, go.sum module inventory edges,
   Maven pom.xml and SBT build.sbt root dependency edges, Mix mix.exs root dependency edges, and NuGet
   project root dependency edges.
2. **License-risk coverage now includes optional source-header presence
   policy.** `license-scan` flags missing and copyleft package manifest
   declarations, missing or mismatched top-level license files, source SPDX
   headers that disagree with package manifests, and, when
   `requireSourceSpdxHeaders` is set, source files without SPDX headers.

## Top picks

Ranked by impact-per-hour:

| # | Module | Why | Cost |
|---|--------|-----|------|
| 1 | `sbom-scan` expansion | Add multi-ecosystem transitive graph enrichment from lockfiles and package-manager metadata. | medium |

## Decision

`secret-scan`, `iac-scan`, `sbom-scan`, and `license-scan` have shipped as
Rust native scanners with module descriptors, tests, result envelopes, and DAG
registration. `sbom-scan` covers first-party dependency manifest inventory;
`license-scan` covers manifest declarations, repository license-file
consistency, SPDX source-header mismatches, and optional source-header
presence policy. Keep the remaining roadmap focused on dependency inventory
depth rather than re-scaffolding scanner work that already exists.

## `secret-scan` — design

- **ID:** `secret-scan`, **category:** `defense`, **rank:** `great`.
- **Tool:** `secret-scan:scan` — pure `ModuleTool` (not a `DagTool`).
  Walks the target directory, applies a curated regex pack to text
  files, and returns `Finding[]` plus a human-readable summary.
- **Detectors:** AWS access keys (`AKIA...`), AWS secret-access-key
  candidates (entropy-gated), GitHub PATs (`ghp_...`, `ghs_...`,
  `gho_...`, `ghu_...`, `ghr_...`), Slack tokens (`xox[bopars]-...`),
  Stripe live/test keys (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`),
  Google API keys (`AIza...`), Anthropic keys (`sk-ant-...`), generic
  OpenAI keys (`sk-...` with high entropy), JWT (`eyJ...`-formatted),
  PEM private keys (`-----BEGIN ... PRIVATE KEY-----`), generic
  high-entropy assignments to suspicious variable names.
- **Filtering:** skips `.git/`, `node_modules/`, `vendor/`, common
  binary extensions, files >2MB. Honors per-finding entropy threshold
  for high-FP-risk patterns.
- **Output:** `Finding[]` with stable fingerprints (`secret-scan:<rule>:<path>:<line>:<digest>`),
  severity by rule, evidence quoting the matched line with the secret
  redacted to its first 4 chars + `***`.
- **No LLM dependency.** Runs in `kuzushi run` headless, in the shell
  via `/use secret-scan; run`, and (later) as a DAG node when wired in.
- **Model usage:** none. The deterministic detection means no
  `enforceAgentQuery` boundary to cross.

## `iac-scan` — shipped Rust scanner

- **ID:** `iac-scan`, **category:** `defense`.
- **Tool:** `iac-scan:scan` with `kind` options for `dockerfile`,
  `github-actions`, `terraform`, or `all`.
- **Coverage:** Dockerfile root-user/floating-image/remote-add/broad-copy
  checks, GitHub Actions `pull_request_target` and broad write-permission
  checks, and Terraform public-ingress/public-S3/database/credential checks.
- **Status:** registered as a built-in deterministic scanner and DAG node;
  emits canonical completed/failed result envelopes and `signal_only`
  core-finding proof state.
