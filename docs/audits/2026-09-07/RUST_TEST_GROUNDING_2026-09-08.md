# Rust test-scope grounding revalidation

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted changes. This follows the [real OpenAI OAuth run](OPENAI_OAUTH_2026-09-08.md).

## What changed

The two serde examples inside the descriptor crate's `#[cfg(test)]` module no longer enter the deterministic surface map, entry-point catalog or model grounding. A shared Rust source projection now removes structurally recognized direct test-only scopes before inventory and surface detection. Production code in the same file retains its line numbers. Tests cover parser calls, inventory routes, Tauri commands, same-line production code, Unicode, misleading comments/string attributes, inner test attributes and conservative handling of malformed or unknown constructs.

Current Rust surface metadata records the extraction policy. Context reuse and explicit catalog grounding refuse older Rust rows with instructions to rebuild context and entry points. Historical models remain intact. The new marker participates in catalog digests while unchanged production surface IDs stay stable. Nonobject legacy metadata retains its original identity and cannot claim the current extraction policy.

This is a bounded repair. Compound cfg expressions, unknown attribute macros, cross-file test-module ownership and general production reachability remain unresolved. A retained row is still a candidate surface. The general line detectors can also match comments or literals outside the excluded scopes; this pass does not claim a complete syntax-aware detector.

## Actual model run

The comparison uses the same six real `kuzushi-descriptor` files, copied byte-for-byte into a fresh workspace. The old model and catalog are preserved in the previous evidence directory. Context and catalog were rebuilt through ordinary `kuzushi run`; the model build used `seedMode=fresh` and the saved GPT-5.5 OpenAI OAuth selection with medium reasoning. No provider or model substitution occurred.

| Evidence | Earlier real run | Fresh real run |
| --- | --- | --- |
| Catalog | Two high-ranked unit-test serde examples | Zero entry-point rows |
| Generated entry points | Based on those test examples | Zero entry-point rows |
| DFD | Four nodes, three flows, one boundary | Four nodes, three flows, three boundaries |
| Model output | Two unverified parser-related hypotheses | Two broad unverified dependency/validation hypotheses |
| Confirmed findings | None emitted | None emitted |

The fresh provider response was HTTP 200 with GPT-5.5 and medium reasoning. The full build completed in 106 seconds, persisted the model, and reopened in the terminal Map summary and DFD. The removed stable IDs, line references and test-function name are absent from the generated document. This is one successful execution, not a latency benchmark or evidence that the target is secure. Provider spend remains unresolved; the zero observed cost is incomplete accounting. The source snapshot is non-Git and the TUI discloses an unknown revision and an unverified model.

## Main remaining problem

Update: the source-body omission below is now corrected and verified with a fresh real model run in [source-code grounding](SOURCE_CODE_GROUNDING_2026-09-08.md). The following paragraph records the earlier run's limitation.

**P1 — Default model grounding lacks relevant source bodies.** The new model explicitly says its source bundle did not include function bodies or line-level definitions. It consequently produces conditional, broad dependency and validation hypotheses. Removing false test surfaces improves honesty but does not supply enough evidence to assess constructors, enum parsing or policy invariants. The next repair should supply bounded, provenance-bound source context for the actual selected components and surfaces, while respecting the existing source budget and untrusted-data boundary. The source bundle currently loads selected context/artifact/document inputs; fresh deterministic grounding primarily supplies inventory, manifests and extracted surface rows. [Source loading](~/vibe-code/Kuzushi/crates/kuzushi-core/src/capabilities/threat_model/application/source_bundle.rs:430), [grounding](~/vibe-code/Kuzushi/crates/kuzushi-core/src/capabilities/threat_model/application/grounding.rs:27).

The successful-Map return to confusing Setup, streaming, fuller response formatting, narrow quit confirmation and the complete Scan/Review/Prove/Fix journey remain open. The OpenCode comparison still supports its persistent conversation, streaming and editor interactions as useful references. No new OpenCode or Claude provider session is claimed here.

## Verification and receipts

Three new regressions failed before the filter and pass after it. The full threat-model group initially found eight current-catalog fixtures missing the new marker; those fixtures were updated while preserving their digest, scope and tamper assertions. Legacy-refusal tests remain separate. The final threat-model group passes 441 tests, the catalog group passes 24, and entry-point TUI checks pass 40. Further final checks, exact binary identities and terminal captures are recorded in the receipt below; overlapping groups are not a full-suite total.

A TUI compile exhausted disk space. Cleaning only regenerable `kuzushi-core` and `kuzushi-tui` Cargo outputs recovered 6.1 GB; the TUI checks then passed. No source, operator credential or historical audit artifact was removed. Source changes remain uncommitted. Review is director self-review, not independent or post-commit review.

[Pass evidence and final verification](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/rust-test-grounding/REVALIDATION.json).

Final quick gate: all checks passed at 2026-09-08 14:32:00 UTC, including the ordinary CRAP-risk gate. The receipt is a dirty working-tree result with `driftedDuringRun=true`, not a clean release receipt. Model execution and the final 80×24 reopening have separate binary receipts; only defensive handling of nonobject metadata and the unsupported-policy recovery wording changed in production between them. No second model request is claimed for that final rebuild.
