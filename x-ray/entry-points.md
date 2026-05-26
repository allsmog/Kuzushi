# Entry Points

Summary: total 8; permissionless 6; role-gated 2; admin-only 0.

| ID | Entry point | Access | Evidence | Review focus |
|---|---|---:|---|---|
| EP-01 | CLI binary invocation | Permissionless-local | `crates/kuzushi-cli/src/main.rs` | Argument validation, exit paths, error handling, safe defaults |
| EP-02 | CLI subcommand dispatch | Permissionless-local | `crates/kuzushi-cli/src/main.rs`, command modules under `crates/kuzushi-cli/src/` | Ensure every subcommand has explicit input/output policy |
| EP-03 | Target repository path and recursive source ingestion | Permissionless-local | Repository path input and artifact threat-model entry describing binary dispatch | Canonicalization, symlink handling, file size limits, ignore rules |
| EP-04 | `.kuzushi` JSON artifact loading | Permissionless-local | `.kuzushi/threat-model.json`, `.kuzushi/runs/*/threat-model.json`, `.kuzushi/runs/*/result.json` | Treat as untrusted, validate schema, bound parse depth and size |
| EP-05 | Artifact KB reads and searches | Permissionless-local | `.kuzushi/v2/artifact-kb.sqlite3` | Prepared statements, read-only open mode where possible, query limits |
| EP-06 | Report and run artifact writers | Permissionless-local | `x-ray/*.md`, `x-ray/architecture.svg`, `.kuzushi/runs/*` | Path containment, atomic writes, no clobber outside repo |
| EP-07 | pi-agent-core/model provider calls | Role-gated | Runtime context and generated artifact workflow | Credential handling, prompt injection resistance, provider timeout and retry policy |
| EP-08 | Environment/configuration inputs | Role-gated | Local CLI provider credentials and `.kuzushi` configuration/state | Secret redaction, precedence rules, no untrusted artifact-driven config changes |

Notes:

- Permissionless-local means any local user, CI job, or wrapper script that can invoke the binary can supply this input.
- Role-gated means meaningful use requires possession of provider credentials or write access to local configuration/secrets.
- No admin-only entry point was identified from the available repository anchors.