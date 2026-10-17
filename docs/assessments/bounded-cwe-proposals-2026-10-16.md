# Bounded systems CWE proposals

The hidden `systems-hunt:deep-semantic-cwe-select` action answers which CWE
classes merit separate investigation, with a rationale from supplied source.
Its former executor ignored declared file/byte limits, used a recursive walk
without directory guards, silently discarded malformed classes, and could
request structured-output repair. Its descriptor could complete Scan and
required a findings store despite producing class proposals.

The action is now auxiliary Labs Map planning under Scope allowance. It cannot
complete Map or Scan, write findings or create discovery jobs. Repository-wide
planning prefixes are explicit; selected discovery scopes remain unsupported.
Existing exact dispatch and `cwes` class fields remain available. The existing
class-input consumer reads explicit handoffs without another query; that does
not qualify the full downstream discovery engine.

Source collection reuses bounded inventory and its entry/byte/cancellation
contracts. Defaults are 80 files, 2048 bytes per prefix and 160 KiB overall;
ceilings are 100,000 files, 256 KiB per prefix and 16 MiB overall. Inventory has
its separate existing 100,000-entry/512-MiB limits and containment rules.
Ignored, uninspected and truncated material remains in the inspection receipt.
A 32-KiB source prompt budget and 8-KiB project/threat-model excerpts disclose
additional omissions. Frozen input is capped at 80 KiB and system text at 16 KiB.
Source identity is captured and checked through the shared bounded snapshot
adapter. Drift preserves the original identity and makes usable output partial.

One fresh tool-free model turn is requested, with 4096 output tokens and no
output-repair loop. Adapter token/turn enforcement varies; all potential
provider requests and transport retries still share the approved allowance.
No model, provider or runtime fallback is introduced. Omitted reasoning keeps
the selected runtime setting; a declared override is explicit.

Model output must fit 64 KiB, contain only `cwes`, and use canonical distinct
CWE ids plus nonempty bounded names/reasons. The default maximum is six classes
and the declared ceiling is 32. Excessive or malformed output fails with its
bounded raw response, supplied text and consumption retained. An empty proposal
establishes no clean-repository claim. Requests, source/context and system text
are inspectable in the saved Replay output and result. Exact context revisions
can be read without activating them globally. Historical reading starts no work
and does not verify current source freshness.

Unknown `data.costUsd` is unavailable and omitted by shared normalization.
Numeric `observedCostUsd` remains an observed subtotal, and `costUsdExact`
indicates completeness. The exported Rust
`DeepSemanticCweOutput` keeps its fields; its legacy numeric cost is the observed
subtotal, qualified by `cost_usd_exact`. Consumers must not interpret an
incomplete observed subtotal as a total dollar charge.

Unrelated legacy options remain declared for compatibility but reject supplied
values instead of silently ignoring them, including stored settings and values
equal to old defaults. Existing aliases remain canonical. Bundled internal
callers project only the selector's declared inputs; other stages retain their
own controls. Two private, unused CWE parsing helpers were removed after a
repository-wide reference check. No module implementation was retired.

Focused checks have source-isolation, charging, unresolved reservation,
cancellation, source drift, strict parsing, alias and explicit class-handoff
evidence. Two KWP sandbox probes initially failed in the outer sandbox and
passed unchanged in the required local environment. The prompt check exposed
an outdated shared role contract; CWE planning now has its own concise contract
instead of unrelated finding-report instructions.

There are 108 distinct focused Rust passes, a passing workspace build and ten
passing summary gates. The risk proxy covers 367 changed code files and its
fifteen support checks pass. The summary receipt is unsigned, dirty and records
drift; exact hashes separately bind the seventeen touched Rust inputs to the
final build. It is local draft evidence, not a publication verification receipt.

Final sequential J317/J304 record 85 machine passes, zero failures, 95 capture
pairs and twelve pending human judgments. All six viewport sizes, no-color
restart and capture provenance were checked on one frozen binary. Thirteen
programs, 4,363 source inputs and 769 runtime inputs stayed unchanged. Fourteen
ANSI cell replays were inspected; they are not OS screenshots or human signoff.
The proposal retains its heading, row position, receipt and paging controls at
40 columns. Source and prompt counts use singular grammar. Scope limitations,
partial coverage and frozen inputs remain readable through paging.

Three earlier native attempts remain archived. The first exposed a verifier
query before allowance-table creation. The second exposed its incorrect
expectation that unavailable cost must be a present null field; the producer
also now uses the canonical observed-cost field. The third completed the flow
but failed a wrapped-text assertion and exposed singular-count copy. Final
passing runs supersede them without erasing their evidence.

Fresh registry comparison covers 189 actions and changes only this descriptor.
The 118-tool visible catalog remains identical. Nine hidden Core actions still
need full qualification, including four with descriptor-only evidence. The
separate deep-semantic discovery engine still uses recursive collection and
fixed 80-file/2048-byte query input. This proposal repair does not qualify it.
Useful live ranking, selected-scope discovery, broad operator UX and reference
parity remain unqualified. Fourteen prior live requests remain spent; no live
allowance remains. Publication stays **Keep as draft** on `main`. All nine broad
milestones remain open. Evidence: `/tmp/kuzushi-cwe-selector-20261016`.

The later [bounded deep-discovery increment](bounded-deep-discovery-2026-10-16.md)
replaces the downstream standalone discovery collector and qualifies its limited
source-to-Review handoff. The earlier checkpoint counts and limits above remain
historical. Live usefulness, bundled legacy stages and full acceptance remain open.
