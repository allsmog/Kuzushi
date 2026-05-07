# `src/prompts` Parity Gap Assessment

`src/prompts/` is runtime-orphaned from the packaged Rust CLI, but it still
captures prompt construction behavior used by unreachable TypeScript agents and
tests. The Rust path has prompt builders and prompt override files, but the
migration ledger does not assert parity for the TypeScript prompt subsystem as
a whole.

## Unasserted Behaviors

1. Template rendering with filters, loops, conditionals, and prompt sanitizing.

   The TypeScript prompt template engine supports dotted path lookup,
   environment values, filters such as `join`, `upper`, `lower`, `default`, and
   `sanitize`, plus nested conditionals and loops
   (`src/prompts/template.ts:4`, `src/prompts/template.ts:7`,
   `src/prompts/template.ts:12`, `src/prompts/template.ts:13`,
   `src/prompts/template.ts:17`, `src/prompts/template.ts:36`,
   `src/prompts/template.ts:52`, `src/prompts/template.ts:80`). The Rust TUI
   prompt editor writes and reads raw `.kuzushi/prompts/<module>/<name>.md`
   override files (`crates/kuzushi-tui/src/app/prompts.rs:226`,
   `crates/kuzushi-tui/src/app/prompts.rs:233`,
   `crates/kuzushi-tui/src/app/prompts.rs:286`,
   `crates/kuzushi-tui/src/app/prompts.rs:356`,
   `crates/kuzushi-tui/src/app/prompts.rs:388`), and module-specific overrides
   such as Carlini read either inline text or a file verbatim
   (`crates/kuzushi-core/src/carlini_threat_hunt.rs:1108`,
   `crates/kuzushi-core/src/carlini_threat_hunt.rs:1118`). No Rust parity row
   asserts a template engine or sanitizer-filter equivalent.

2. Layered prompt tool-policy resolution.

   TypeScript prompts include a policy layer resolver with named tool groups,
   allow/deny lists, global defaults, task-level policy, and config-level
   overrides (`src/prompts/tool-policy.ts:1`, `src/prompts/tool-policy.ts:27`,
   `src/prompts/tool-policy.ts:54`, `src/prompts/tool-policy.ts:90`,
   `src/prompts/tool-policy.ts:102`, `src/prompts/tool-policy.ts:129`,
   `src/prompts/tool-policy.ts:136`). Rust has an `AgentToolPolicy` object and
   a whitebox-static helper that selects either read-only tools or the default
   policy (`crates/kuzushi-core/src/runtime.rs:98`,
   `crates/kuzushi-core/src/whitebox_static.rs:119`,
   `crates/kuzushi-core/src/whitebox_static.rs:134`,
   `crates/kuzushi-core/src/whitebox_static.rs:165`,
   `crates/kuzushi-core/src/modules/taint_iris.rs:230`), but no asserted Rust
   equivalent for the TypeScript prompt-layer merge semantics or named tool
   groups.

3. Language-specific prompt tuning and few-shot assembly.

   The TypeScript prompt layer maps task IDs to vulnerability classes and emits
   language/framework-specific dangerous sinks, safe patterns, few-shot
   examples, investigation hints, anti-hallucination extras, and general search
   guidance (`src/prompts/language-tuning.ts:14`,
   `src/prompts/language-tuning.ts:53`,
   `src/prompts/language-tuning.ts:68`,
   `src/prompts/language-tuning.ts:79`,
   `src/prompts/language-tuning.ts:88`,
   `src/prompts/language-tuning.ts:98`,
   `src/prompts/language-tuning.ts:124`,
   `src/prompts/language-tuning.ts:159`,
   `src/prompts/language-tuning.ts:189`). Rust agentic SAST currently builds a
   generic repository inventory prompt with severity, max findings, exclude
   patterns, evidence requirements, optional whitebox block, and source snippets
   (`crates/kuzushi-core/src/modules/agentic_sast.rs:459`,
   `crates/kuzushi-core/src/modules/agentic_sast.rs:466`,
   `crates/kuzushi-core/src/modules/agentic_sast.rs:480`,
   `crates/kuzushi-core/src/modules/agentic_sast.rs:482`,
   `crates/kuzushi-core/src/modules/agentic_sast.rs:491`). That is useful, but
   the language profile and few-shot subsystem is not asserted as ported.

4. Prompt module reports and stability tests remain TypeScript-only fixtures.

   `src/prompts/prompt-report.ts`, `src/prompts/modules.ts`, and the prompt
   test suite encode report formatting and stability expectations that are not
   tied to a current Rust module row. Rust prompt overrides are operator files
   and shell commands (`crates/kuzushi-tui/src/app/prompts.rs:200`,
   `crates/kuzushi-tui/src/app/prompts.rs:400`), while Rust module prompts are
   embedded in each executor (`crates/kuzushi-core/src/modules/agentic_sast.rs:459`,
   `crates/kuzushi-core/src/threat_model.rs:395`,
   `crates/kuzushi-core/src/systems_hunt.rs:1150`). The parity claim is
   therefore per-tool, not subsystem-wide.

## Recommendation

Keep `src/prompts/` as a reference fixture while the remaining TypeScript
caller graph exists. If the Rust product needs this behavior, port it as a
small explicit prompt library with tests rather than reintroducing the
TypeScript prompt subsystem into the runtime path.
