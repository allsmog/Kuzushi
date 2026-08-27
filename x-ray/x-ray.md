# Kuzushi Pashov X-Ray

Repository: `Kuzushi`
Path: `/workspace/Kuzushi`

## X-Ray Verdict
WATCH

Kuzushi appears to be a local Rust CLI/workflow that ingests an arbitrary repository, prior `.kuzushi` artifacts, and model output to produce threat-model and x-ray reports. The known primary binary entry point is `crates/kuzushi-cli/src/main.rs`, which parses CLI args and dispatches subcommands. No public network listener is evident from the available anchors, but the effective boundary is broad: untrusted source files, local filesystem writes, SQLite artifact KB content, LLM/provider calls, and generated Markdown/SVG/JSON. Keep the project under WATCH until path containment, prompt/tool isolation, artifact sanitization, and secret redaction are proven in code and tests.

## Source Anchors

- CLI binary: `crates/kuzushi-cli/src/main.rs`
- Local threat-model artifact: `.kuzushi/threat-model.json`
- Run artifacts: `.kuzushi/runs/*/threat-model.json`, `.kuzushi/runs/*/result.json`
- Normalized threat model: `.kuzushi/runs/92033064-b2d1-416b-8036-1e6722c0e6c9/threat-model-output/normalized-threat-model.json`
- Artifact KB: `.kuzushi/v2/artifact-kb.sqlite3`
- Expected report outputs: `x-ray/x-ray.md`, `x-ray/entry-points.md`, `x-ray/invariants.md`, `x-ray/architecture.svg`

## Architecture Snapshot

- Local user or CI invokes the Kuzushi CLI.
- CLI dispatches commands that scan a target repository and read or write `.kuzushi` state.
- Artifact and threat-model data is loaded from JSON files and the SQLite artifact KB.
- pi-agent-core/model orchestration sends selected context to external model providers and consumes model output.
- Generated audit artifacts are written back to the workspace under `x-ray/` and `.kuzushi/runs/`.

## Highest-Value Review Areas

1. Path containment: canonicalize repo paths, output paths, and artifact paths; reject symlink escapes and parent traversal.
2. Prompt and tool isolation: treat repository files, artifacts, and model output as adversarial data; never let model text directly select filesystem or shell actions without policy checks.
3. SQLite artifact KB safety: use prepared statements, bounded query sizes, read-only mode where possible, and corruption handling.
4. Secret hygiene: redact API keys, environment variables, filesystem secrets, and provider responses before storing logs or reports.
5. Artifact integrity: isolate run directories, avoid clobbering, and prevent stale `.kuzushi` state from silently changing current behavior.
6. Resource limits: bound recursive scans, prompt size, JSON parsing depth, report size, and provider retries.

## Pre-Audit Risk Posture

- Critical remote-exploit surface: low, assuming this remains a local CLI with no exposed listener.
- Local data-exfiltration surface: medium to high because untrusted repos can influence prompts and generated artifacts.
- Integrity surface: medium because `.kuzushi` artifacts and model responses can influence future reports.
- Availability surface: medium because malicious repositories can contain large files, deep trees, malformed JSON, or hostile SQLite inputs.

## Suggested Pre-Audit Tests

- Malicious repo with symlinks from `x-ray/` or `.kuzushi/` to files outside the repo.
- Source file containing prompt-injection instructions that attempt to exfiltrate env vars or alter tool policy.
- Corrupt or attacker-created `.kuzushi/v2/artifact-kb.sqlite3`.
- Oversized files, deep directory trees, recursive symlinks, and very large JSON artifacts.
- Concurrent runs targeting the same repository.
- Provider failure, timeout, partial JSON, and hostile Markdown/SVG output cases.
