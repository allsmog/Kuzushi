# Upstream OpenAI Codex

Kuzushi ships as Kuzushi. OpenAI Codex is the upstream agent-shell substrate
that Kuzushi tracks for agent runtime, shell, and command-loop ideas where they
are useful. Public product identity, docs, package names, binaries, prompts,
artifacts, and cybersecurity modules are Kuzushi-owned.

## Upstream Source

- Repository: https://github.com/openai/codex
- License: Apache-2.0. The upstream license text is retained in
  `LICENSES/Apache-2.0.txt`, and distribution notices are recorded in
  `NOTICE`.
- Local remote: `upstream-codex`.

If the remote is missing in a fresh clone, add it with:

```bash
git remote add upstream-codex https://github.com/openai/codex.git
git fetch upstream-codex
```

## Sync Strategy

Kuzushi tracks Codex through the `upstream-codex` remote rather than committing
a wholesale upstream subtree. That keeps the shipped tree Rust-first and
Kuzushi-branded while making upstream review explicit.

Recommended sync flow:

1. Fetch upstream into remote-tracking refs:

   ```bash
   git fetch upstream-codex
   ```

2. Review candidate changes against the current upstream branch:

   ```bash
   git log --oneline --decorate main..upstream-codex/main
   git diff --stat main..upstream-codex/main
   ```

3. Port only the small substrate changes Kuzushi needs. Keep patches cohesive
   and mapped to Kuzushi boundaries instead of copying whole files.
4. Record material ports in this file under "Local Patches".

Do not rename Kuzushi back to Codex in public surfaces during a sync. Internal
adapter names may mention Codex only when they refer to the upstream provider,
OAuth flow, SDK, or sync source.

## Kuzushi-Owned Surface

The following areas are Kuzushi-owned and should not be overwritten by an
upstream import:

- Rust CLI binary and npm wrapper: `kuzushi`, with optional `kz` alias.
- Rust Ratatui shell, command parser, prompt, header, blue terminal theme, and
  Metasploit-style module cockpit.
- `.kuzushi/runs/<runId>/` artifacts, `events.jsonl`, failure handoff context,
  finding schema, proof states, and report outputs.
- DDD security domains: context, threat model, attack surface, modules,
  findings, proof, run trace, scanners, triage, verify, report, UI view
  models, UI theme, and UI views.
- Kuzushi cybersecurity modules, scanner adapters, triage, verification,
  recommender, and suggest-only patch workflow.
- No-silent-model-fallback enforcement.

## Local Patches

No upstream Codex source files are currently vendored wholesale in this tree.
When a Codex change is ported, add a dated entry here with:

- upstream commit or release tag;
- Kuzushi files changed;
- behavior intentionally kept Kuzushi-specific;
- license or NOTICE impact.
