# Source evidence and real OpenAI OAuth Map

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening. This follows the [Rust test-scope revalidation](RUST_TEST_GROUNDING_2026-09-08.md).

## Outcome

OpenAI OAuth with GPT-5.5 and medium reasoning completes a fresh model-backed Map. Default source input now includes actual code, fixing the previous six-file run's lack of function bodies. The new analysis explains concrete approval derivation, prompt-path construction, optional path semantics, and phase classification. These are conditional model hypotheses about the selected library, not confirmed vulnerabilities in Kuzushi's downstream dispatch or path enforcement.

The existing OAuth credential was reused. No provider/model substitution, credential copy, commit, or push occurred. The ordinary CLI executable ran context building, entry-point extraction, and fresh threat-model generation. The rebuilt executable then reopened its persisted Map in an owned terminal.

## Before and after

Both model runs used the same six unchanged real `kuzushi-descriptor` files, each in a fresh workspace. Neither run seeded from its predecessor.

| Evidence | Previous run | Source-code run |
| --- | --- | --- |
| Model input | Inventory, manifests, context, selected surfaces | Same inputs plus 50,671 bytes of source projection; no coverage truncation |
| Deterministic entry points | 0 | 0 |
| Model-generated candidates | 0 | 9 public library methods/functions; shown as model only |
| DFD | 4 nodes, 3 flows, 3 boundaries | 7 nodes, 7 flows, 2 boundaries |
| Hypotheses | 2 broad dependency/validation hypotheses | 4 hypotheses citing concrete code and downstream preconditions |
| Findings emitted | 0 | 0 |
| Single-run elapsed time | 106 seconds | 214 seconds |

The timing is one observation per run, not a benchmark. Provider spend remains unresolved; zero observed cost does not mean free. The source snapshot is non-Git, and Map discloses an unknown revision and an unverified model. More nodes or hypotheses are not a quality score: the meaningful improvement is that the model now names and explains actual implementation behavior while identifying the missing downstream evidence.

For example, it correctly explains that `ToolPolicy::new` derives explicit approval from `ToolEffect::needs_operator_approval`, and that `relative_prompt_override_path` constructs a path without itself doing filesystem I/O. It leaves open which downstream consumers validate the metadata and confine paths. It does not establish that those consumers are vulnerable. [Policy constructor](~/vibe-code/Kuzushi/crates/kuzushi-descriptor/src/tool_policy.rs:75), [path helpers](~/vibe-code/Kuzushi/crates/kuzushi-descriptor/src/prompt_paths.rs:11).

## Implementation and limits

The canonical `sources` option now defaults to `context,source-code,threat-model`. Explicit lists retain their meaning; `sources=none` and the default bundle with `contextMode=off` exclude code. `seedMode=fresh` excludes the prior model while retaining code. Shared source loading supplies single/staged synthesis, gap filling, and refinement. Staged/refine citation validation includes the supplied code references, including references outside refinement's short anchor list.

Collection uses the selected scope's inventory, prioritizes selected surface locations, and distributes remaining files across components. Whole source lines carry workspace-relative references and file hashes. Small files fit completely; larger inputs report omissions under `maxSourceBytes` and `contextLimit`. File reads have explicit ceilings and containment checks. Source text remains untrusted. Tree drift, stale catalog identity, and incomplete inventories stop collection; cancellation is checked during inventory traversal and between selected files. [Collector](~/vibe-code/Kuzushi/crates/kuzushi-core/src/capabilities/threat_model/application/source_code/mod.rs:22), [operator contract](../../modules.md#source-evidence-for-model-backed-map).

This does not supply whole-program reachability, arbitrary unrecognized file types, or unseen downstream code. Large scopes can still have partial source coverage. Rust uses the bounded test-scope projection from the preceding pass; compound cfg expressions, unknown macros, cross-file test ownership, and general comment/string detector false positives remain open. The generated candidates are distinct from deterministic extraction and security proof.

## Terminal acceptance and remaining interaction defect

The persisted Summary and DFD reopened at 120×36 and 80×24. The entry browser truthfully reports **0 extracted, 9 modeled, 9 model only**. No new OpenCode or Claude provider session is claimed; their earlier comparison remains relevant to persistent conversation, streaming, editing, and readable evidence.

**P1 at this checkpoint — Entry-point detail is impractical at 80×24.** Header/receipt rows and the stacked list leave one visible detail row. Page Down moves the detail from `rows 1-1/26` to `rows 11-11/26`, skipping nine rows in that view. The footer also omits the detail paging hint. This reproduced an evidence-reading problem with real generated data; the source-grounding change alone did not resolve it. [Before](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/source-code-grounding/map-entry-80x24.txt), [after Page Down](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/source-code-grounding/map-entry-pagedown-80x24.txt).

**Subsequent status: corrected in the tested working-tree frames.** The entry-reading pass uses this unchanged model, exposes five detail rows at 80×24, and pages through every row by the actual viewport height. Full identity and receipt text remain reachable; resize, zoom and typing preserve their intended ownership. [Repair and acceptance](ENTRY_DETAIL_READING_2026-09-08.md).

Successful foreground Map completion returning to confusing Setup, streaming, and full Scan/Review/Prove/Fix/Report acceptance remain open. Headless completion followed by restart does not test that foreground transition. The broad interaction checklist remains incomplete.

## Verification

The default-prompt regression failed before the change while explicit source exclusion already passed. The full threat-model group now passes 456 tests, including actual registry-boundary prompt capture for single synthesis, staged synthesis/gap filling, refinement, explicit sources, and nested-scope citations. Collector checks cover byte budgets, Unicode, late surface locations, component selection, invalid text, read ceilings, external symlink replacement, tree mismatch, and cancellation. After the final refinement citation wording change, all five question-closer checks pass. These groups overlap.

The normal CRAP-risk gate and repository quick gate passed. Final receipts record the last gate outcome, source hashes, and exact executable identities. The real model execution and final terminal reopening use separate binary receipts: only refinement citation guidance changed in production between those builds; single-build input was unchanged. No second model request is implied. This is a dirty working-tree check, not release certification, and review is director self-review rather than independent or post-commit review.

[Execution, source, terminal, and final verification receipts](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/source-code-grounding/REVALIDATION.json).

Subsequent checkpoint: [foreground Map completion and acceptance](MAP_COMPLETION_2026-09-08.md) now have real OAuth, explicit acceptance and restart evidence. Earlier open-status statements above describe this pass’s checkpoint.
