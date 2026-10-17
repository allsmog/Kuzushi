# Bounded chunk inventory and readable partial plans

The retained chunk planner had its own recursive directory walk and read entire
oversized files while deriving source windows. Source planning now builds one
shared bounded repository inventory for unscoped work. It preserves the shared
100000-entry, 512 MiB inspection and 256 KiB per-file inspection limits,
iterative filesystem traversal, cancellation and containment. Loose root files
remain eligible. Ignored, generated, vendor, symlink and language exclusions
remain visible in the planning receipt.

When a Git index exists, unscoped planning follows the shared inventory's tracked
selection. Untracked files can be named through an explicit scope. Explicit
scopes preserve literal membership, including non-C and vendor sources, without
walking the repository. Source planning has a separate 100000-file and 512 MiB
selected-source bound. Window-planning reads are charged against selected source
bytes before reading. Oversized files stream through bounded buffers and
line-aligned windows; they are no longer loaded whole. Overlong lines, invalid
text and unavailable sources produce disclosed omissions rather than invalid
windows or silent skips.

The new optional `InventoryInspection.enumeration_complete` field distinguishes
incomplete enumeration from prefix-only content inspection. It remains unknown
on legacy receipts. This prevents an earlier per-file warning from hiding a
later entry limit. Planning does not infer completeness from error text.

`FullModePlan.coverage` records inventory, selection, limits, exclusions,
omissions, source bytes, window reads and cancellation. Partial plans remain
readable but cannot reach chunk model requests. Execution does not
automatically exclude more source, subdivide the repository or create jobs.
Retry/cache policy and exact source-window delivery remain intact. Fresh review
is required because membership and chunk IDs can change. Optional JSON fields
preserve legacy deserialization; Rust struct literals must initialize the new
fields, as documented in `RELEASING.md`.

## Native reading repair

The initial J309 machine checks passed, but visual inspection exposed a real
reading problem at 40 columns: the partial receipt led with chunk counts and
left the omitted file several pages down. The final headline names an omitted
source and says that no scan ran. Cancellation and incomplete enumeration also
have explicit headlines. Detailed geometry, source limits and receipts remain.

This presentation is shared by headless and shell output. The final native
case asserts that `oversized.c` is visible on the initial 40-column screen.
Both initial runs and their frozen inputs remain under the evidence root.

## Verification

Evidence root: `/tmp/kuzushi-bounded-chunks-20261016`; final evidence is in
`readable-partial`.

All 498 distinct focused Core checks pass: 64 full-mode checks, 19 chunked-input
contracts, 113 inventory checks, 58 shared-preparation checks, 97 scan-orchestration
checks, 69 registry checks and 78 scope-consumer checks. They cover deep trees,
symlink cycles, literal membership, aggregate limits, sparse-file refusal before
window reads, cancellation, long lines, UTF-8, source-window offsets, typed
enumeration state, partial execution refusal and compatible historical reading.
The workspace binary build, architecture and all ten summary gates pass. The
risk gate passes for 254 changed code files and all 15 support checks.

The development receipt is unsigned, dirty and records `driftedDuringRun: true`.
It is not a clean publication receipt. Final documentation and whitespace checks
are recorded separately.

Final sequential native runs use the same frozen build:

- J309, `native/J309/20261016-120540/J309`: 18 machine passes, zero failures,
  16 capture pairs and three pending human judgments. A deep tree and symlink
  cycle terminate with explicit exclusions. The oversized sparse file is omitted
  before window reads. Partial planning stays partial through restart. A new
  explicit scope plans only the named vendor source. Export retains zero findings,
  with no jobs, observations, decisions or provider reservations. Small fixture
  files retain exact hashes. The sparse file is checked by metadata only; its
  contents are not authenticated.
- J306, `native/J306/20261016-120618/J306`: 30 machine passes, zero failures,
  37 capture pairs and four pending human judgments. Selected retry IDs, cache
  policy, outside/empty scope refusal, narrow reading, export and no-color
  restart remain intact. Planning does not become primary Scan evidence.
- J304, `native/J304/20261016-120744/J304`: 55 machine passes, zero failures,
  54 capture pairs and seven pending human judgments. Three baseline and three
  context-experiment jobs complete within one six-call intercepted allowance.
  Actual adapter requests contain the frozen reviewed lesson context. Six raw
  observations and one historical human policy decision remain. Report requires
  source reassessment, retirement blocks future lesson use and restart adds no
  work. Intercepted transport does not measure model accuracy.

All 13 native programs, 4314 source inputs and 748 runtime inputs retain their
frozen hashes during all three final journeys. The executable SHA-256 is
`9b39e264cb0d44f9e0ac74de2e8300021b7b18899c476a7272f56bf63267c87b`.
`readable-partial/native-evidence.json` authenticates dimensions, capture hashes
and no-color output. Selected ANSI cell replays were visually inspected,
including partial reading, separate spending authority, lesson text and source
review at 40 columns. They are not OS screenshots or human UX acceptance.
All three journeys retain `REVIEW_REQUIRED`.

Live chunked precision, source-version isolation, late execution failure retention
and complete resource/accounting qualification remain open. The alias stays
Compatibility. Eighteen hidden Core actions and the original nine delivery
milestones still need full reconciliation. Human UX and larger-history acceptance
remain open. Earlier approved real experiments remain fourteen requests; this
increment adds none. Exploit development, reproducers and vulnerability patching
remain excluded. No commit or push is made, and the earlier publication proposal
and staged report patch remain separate.
