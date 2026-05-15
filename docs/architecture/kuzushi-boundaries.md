# Kuzushi Boundaries

Kuzushi is a Rust-first security-agent app. The upstream agent-shell substrate
is not the product boundary. The product boundary is Kuzushi's cybersecurity
harness, module cockpit, artifacts, proof workflow, and TUI.

## Required Contexts

| Context | Owner | Allowed responsibilities |
| --- | --- | --- |
| `context` | `crates/kuzushi-core/src/context.rs` plus context modules | Repository inventory, language/framework/package detection, file index, deterministic app model inputs. |
| `attack_surface` | `crates/kuzushi-core/src/attack_surface.rs` | Routes, auth/session boundaries, sinks, stores, jobs, clients, trust boundaries, deterministic risk ranking inputs and outputs. |
| `threat_model` | `crates/kuzushi-core/src/threat_model.rs` | STRIDE, PASTA/DREAD artifacts, DFD data, threat stories, deterministic degradation. |
| `modules` | `crates/kuzushi-core/src/modules` | Tool descriptors, input preparation, dispatch, output envelope normalization. |
| `recommender` | `crates/kuzushi-core/src/capabilities/module_recommender` | Read context, threat, attack surface, capabilities, and findings to suggest next tools. No execution. |
| `scanners` | Rust scanner facade and `crates/kuzushi-core/src/scan` | Normalize deterministic scanner output into findings. No triage. |
| `findings` | `crates/kuzushi-core/src/findings` | Finding identity, aliases, severities, evidence, suppressions, persistence. No scanner/LLM/subprocess/render calls. |
| `proof` | `crates/kuzushi-core/src/proof` | Static proof policy, citation validation, proof state transitions. |
| `triage` | `crates/kuzushi-core/src/triage.rs` and module triage code | Attach verdicts to existing findings. |
| `verify` | `crates/kuzushi-core/src/verify.rs` and `crates/kuzushi-core/src/verification` | Attach proof outcomes and empirical verification records. |
| `patch` | `crates/kuzushi-core/src/patch` and remediation code | Suggest diffs and validate only when approved/configured. |
| `report` | `crates/kuzushi-core/src/report.rs` and `crates/kuzushi-core/src/report` | Read artifacts/findings and produce report output. No execution. |
| `run_trace` | `crates/kuzushi-core/src/run_trace.rs` and `crates/kuzushi-core/src/run_artifacts` | Run IDs, events, trace, summaries, failure handoff, artifact manifest. |
| `failure` | `crates/kuzushi-core/src/run_artifacts/run_failures.rs` | Bounded fallback context for partial/failed runs. |
| `ui_*` | `crates/kuzushi-tui/src/ui_view_models.rs`, `ui_theme.rs`, `ui_views.rs` | View models, semantic styles, and rendering over already-shaped state. |

## Dependency Rules

- Findings never call scanners, LLM runtimes, subprocesses, or renderers.
- Scanners normalize findings and never triage.
- Triage attaches verdicts and does not mutate scanner evidence.
- Verify attaches proof outcomes and must be the source of empirical proof.
- Patch suggests diffs unless an explicit approval path enables validation.
- Report reads artifacts and findings only.
- Recommender reads context, threat model, attack surface, capabilities, and
  findings but does not execute modules.
- UI consumes view models and artifacts. It must not execute modules directly.
- Model/provider selection must use explicit configuration or tool input. No
  silent model fallback is allowed.
- Code may not say "validated" unless verification or an equivalent empirical
  check actually ran.

## Enforcement

The architecture gate is:

```bash
pnpm quality:architecture
```

It currently verifies that the required boundary files exist and blocks the
highest-risk dependency violations:

- findings calling scanners, runtimes, renderers, or subprocesses;
- scanners calling triage or verification;
- triage calling scanners, verification, patch, report, tool dispatch, or
  subprocesses;
- verify calling scanners, triage, patch, report, or tool dispatch;
- report code dispatching scanners/runtimes/subprocesses;
- recommender executing modules;
- failure handoff dispatching tools, runtimes, scanners, verification, or
  subprocesses;
- TUI renderers dispatching runtime/tool execution;
- TUI view models and view state dispatching runtime/tool execution;
- TUI runtime code using "validated" wording for states that are only checked
  or parsed;
- Home/Recommend catalog renderers parsing artifacts directly instead of using
  `ui_view_models`;
- the Runs ledger renderer parsing run summaries directly instead of using
  `ui_view_models`;
- Replay/Trace renderers parsing run artifacts directly instead of using
  `ui_view_models`;
- Module Detail renderers walking prompt override files directly instead of
  using `ui_view_models`;
- Threat renderers loading persisted threat-model artifacts directly instead of
  using `ui_view_models`.

The gate is a floor. When adding a new boundary, update
`scripts/check-ddd-boundaries.mjs` with the new source roots and forbidden
dependencies.
