# Option input surfaces audit

Date: 2026-08-24
Scope: Map and phase task outcomes, planning option editing, guided options, the Options screen, and direct `run` input
Method: three read-only lenses covering interaction state, typed input, and presentation

Pre-fix evidence line numbers below record the audit-time locations; the
remediation table cites the current implementation and regression tests.

## Verdict

**FAIL.** Cached Map work has contradictory Space/F5/`g` controls, and several shell surfaces expose raw JSON even when the operator is changing one primitive value.

## Remediation status

**RESOLVED.** The findings below describe the pre-fix behavior. The implemented
contract is now:

| Surface | Resolution | Regression proof |
|---|---|---|
| Cached Map task | Space owns the complete `REUSE → RUN → SKIP` cycle; running fresh preserves dependency rules and skipped rows cannot retain hidden rebuild state. | `crates/kuzushi-tui/src/app/onboarding/controls.rs:69`, `crates/kuzushi-tui/src/app/onboarding/controls.rs:366`, `crates/kuzushi-tui/src/app/tests.rs:20089` |
| Map option pane | The serialized canonical-input block is gone. The pane shows the selected value, source, input kind, choices or bounds, edit action, and description with deliberate spacing. | `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:114`, `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1343`, `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1838` |
| Interactive option discovery | Unstructured workflow handoffs are excluded from Map, guided questions, and the global Options table until their descriptors provide field-level schemas. | `crates/kuzushi-tui/src/app/options/options_filter_label.rs:32`, `crates/kuzushi-tui/src/app/guided_scan/mod.rs:228`, `crates/kuzushi-tui/src/ui_view_models/options/tests.rs:177` |
| Primitive values | Booleans render as yes/no, string lists as comma-separated values, and compound stored values as counts rather than serialized objects. | `crates/kuzushi-tui/src/app/options/options_filter_label.rs:71`, `crates/kuzushi-tui/src/app/options/tests.rs:73` |
| Direct shell run | The catalog advertises `run <tool> [key=value ...]`; values use descriptor coercion and structured workflow fields are refused. Legacy object input remains accepted but is not advertised. | `crates/kuzushi-tui/src/commands/shell_command_specs/run_scan.rs:23`, `crates/kuzushi-tui/src/app/tool_runner/run_tool/dispatch.rs:296`, `crates/kuzushi-tui/src/app/tool_runner/run_tool/dispatch.rs:312` |

Focused interaction, renderer, guided-option, direct-run, descriptor, formatting,
and CRAP-risk checks pass after remediation.

## Findings

### High — cached task outcomes do not form one truthful cycle

Space only toggles selection, while F5 mutates the separate rebuild set. On a cached row this makes `REUSE → SKIP` the Space behavior; regeneration is unreachable from Space. Turning F5 rebuild off removes selection too, but logs reuse. A stale rebuild flag can also survive deselection and restore an unexpected run when the phase reopens.

Evidence: `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:914`, `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:984`, `crates/kuzushi-tui/src/app/view_state/routes/pickers.rs:653`, `crates/kuzushi-tui/src/app/onboarding/controls.rs:114`.

Failure scenario: an operator focuses `Gather repo context`, sees `REUSE`, presses Space expecting regeneration, and instead skips it. Following the visible `g` instruction types into the command composer rather than changing the outcome.

### High — Map presents internal JSON as if it were operator input

The option pane serializes the entire prepared tool input under `CANONICAL INPUT` for every selected field, including integers, booleans, and enums. Tests explicitly require this projection.

Evidence: `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1478`, `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1522`, `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1935`.

Failure scenario: while changing `Sample limit`, the operator is shown `{"discovery":...,"sampleLimit":200}` and reasonably concludes that JSON must be edited.

### High — structured options have no UI-editable schema

`OptionType::Json` describes neither object fields nor list items, and core coercion accepts any JSON value. The UI therefore cannot derive primitive sub-editors, while malformed shapes fail later in executors.

Evidence: `crates/kuzushi-descriptor/src/descriptor_model.rs:155`, `crates/kuzushi-core/src/modules/options/json_summary.rs:145`, `crates/kuzushi-core/src/modules/threat_intel_module.rs:139`, `crates/kuzushi-core/src/capabilities/threat_intel/application/harvest_input.rs:6`.

Failure scenario: `threat-intel:harvest.cves=true` passes option coercion but fails when the executor expects an array of strings.

### High — direct run advertises raw JSON as the normal argument

The command catalog says `run <tool> [json]`, and dispatch parses the entire optional argument with `serde_json::from_str`.

Evidence: `crates/kuzushi-tui/src/commands/shell_command_specs/run_scan.rs:23`, `crates/kuzushi-tui/src/app/tool_runner/run_tool/dispatch.rs:178`.

Failure scenario: a user must construct and quote a complete JSON object to change one boolean or number before launching a tool.

### Medium — the Options screen points every type at one command string

Scalar coercion is centralized and sound, but the Options screen is a static seven-column table. It serializes compound defaults and values and directs every row to `set <key> <value>`, including `json` rows.

Evidence: `crates/kuzushi-tui/src/ui_view_models/options.rs:210`, `crates/kuzushi-tui/src/ui_view_models/options.rs:240`, `crates/kuzushi-tui/src/renderer/views/options/mod.rs:39`.

Failure scenario: opening advanced options presents a structured value as editable without supplying a field-level editor.

### Medium — option-pane density has weak hierarchy

At common terminal widths the layout uses a rigid 50/50 vertical split. The option list, repeated key/value/source detail, and canonical JSON are packed at the top, while unused space appears only after all content.

Evidence: `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:98`, `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1172`, `crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:1602`.

Failure scenario: the active editing action is visually subordinate to repeated metadata even though the pane has ample room.

## Lens verdicts

| Lens | Verdict | Primary failure |
|---|---|---|
| Task outcome semantics | FAIL | Split selection/rebuild state produces contradictory transitions |
| Typed primitive input | FAIL | JSON options lack schema; direct run requires object syntax |
| Option presentation | FAIL | Full serialized input and dense repeated metadata dominate the editor |

## Prioritized fixes

1. Make Space atomically cycle cached available tasks `REUSE → RUN → SKIP → REUSE`, while preserving dependency rules and eliminating orphan rebuild flags.
2. Remove the canonical JSON preview and replace it with type-specific primitive editing guidance.
3. Exclude unstructured `OptionType::Json` handoffs from interactive option editors until a descriptor supplies field-level schema; keep them available to internal prepared dispatch.
4. Advertise and parse `run <tool> key=value ...` through the same descriptor coercion used by planning and `set`.
5. Recompose the pane around list, selected field, and editing guidance with deliberate spacing; keep compact terminals informative.

## Not covered

- Redesigning the published manifest schema for typed nested objects.
- Changing internal JSON artifacts, run receipts, or module-to-module handoffs.
- Replacing file-backed imports where a path already provides the primitive operator surface.
