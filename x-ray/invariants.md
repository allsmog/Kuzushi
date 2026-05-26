# Invariants

## Global Security Goals

- G-1: All reads and writes initiated for a target repository remain inside the intended repository root unless the user explicitly supplies and confirms an external path.
- G-2: Repository contents, `.kuzushi` artifacts, SQLite rows, provider responses, and generated reports are untrusted data, not instructions.
- G-3: API keys, environment variables, filesystem secrets, and provider credentials are never written to `.kuzushi`, `x-ray/`, logs, or prompts unless explicitly redacted and approved.
- G-4: Each run is isolated and reproducible enough to distinguish fresh outputs from stale or attacker-seeded artifacts.

## Internal Code Invariants

- I-1: Every user-supplied path is canonicalized before use, and symlink escapes are rejected for scans and writes.
- I-2: SQLite artifact KB access uses parameterized queries and bounded result sizes; user or model text is never concatenated into SQL.
- I-3: JSON and Markdown/SVG generation escapes or neutralizes untrusted content where it can affect rendering, links, scripts, or downstream tooling.
- I-4: Model output cannot directly invoke shell commands, select arbitrary files, change provider configuration, or overwrite artifacts without deterministic policy checks.
- I-5: `.kuzushi` artifacts loaded from previous runs must pass schema validation and cannot silently override current CLI flags or secrets.
- I-6: File scans, prompt construction, parsing, retries, and report writing have explicit size, depth, and timeout limits.
- I-7: Output writes are atomic and collision-safe; concurrent runs cannot corrupt shared state or clobber unrelated files.

## Cross-Boundary Threat Invariants

- X-1: Prompt-injection text from source files or artifacts may influence summaries, but never the trusted control plane.
- X-2: External model-provider responses are validated against expected schemas before being used as structured data.
- X-3: Malformed, corrupt, or attacker-created artifact KB files fail closed with a clear error, not partial trust.
- X-4: Any subprocess or git interaction, if present, passes arguments without shell interpolation and runs with least necessary working-directory access.

## Emergency and Environmental Invariants

- E-1: If secret leakage is detected in any generated artifact, the run must fail or mark the artifact unsafe and provide a deletion/remediation path.
- E-2: If provider calls fail, timeout, or return invalid structured data, Kuzushi must not reuse stale successful output as if it came from the current run.
- E-3: If path containment cannot be proven for an output path, writing is denied by default.