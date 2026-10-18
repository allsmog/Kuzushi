# Findings by recorded discovery scope

Operators can open saved findings from an accepted boundary with `v` or the
searchable scope action menu. The query pins the exact accepted record and
spans saved studies. Back restores the boundary cursor, reading position,
composer, original finding filter and selected study. Draft boundaries and the
file reader cannot trigger this action. Reading starts no discovery or model
work and does not activate context.

`findings:list` declares `scopeId` (aliases `scope`, `scope_id`) and `scopeRecord`
(alias `scope_record`). Expressions use `scope:<id>` and `scope-record:<hash>`.
Ids are case sensitive. Without an exact record, a scope id matches all recorded
accepted revisions of that id. Record filters require the complete 64-character
hash. The dedicated CLI exposes `--scope` and `--scope-record` through the same
parser and workspace page reader. Existing unfiltered list output is unchanged.

Membership comes from authenticated request artifacts and accepted proposal
records for ledger observations. A path match cannot assign a finding to a
scope. Matching precedes pagination and retains whole-ledger aliases and human
decisions. Older matching observations remain represented when a newer
observation becomes the current consolidated row. Scope, run, study and source
constraints must match the same observation run. The view does not replace the
current ledger row with an old verdict or claim that source was fixed.

The page adds `scopeFilter` with matched run ids, accepted references, unbound
run counts and unavailable metadata. Missing or altered request/proposal data
is disclosed and excluded from known matches. TUI headers name partial scope
history; plain output names unavailable runs. New grouping requests refuse
partial scope history because their older return type cannot carry that
receipt. Current Review completion still uses its unfiltered source-qualified
corpus, so a scope view cannot forge phase completion.

The dedicated CLI returns its first window; use the shared paged tool for
continuation. The reader checks at most 4096 candidate observation runs and authenticates at
most 1 MiB per request artifact. Run-prefix and exact study membership narrow
candidates before the cap. Exceeding the cap fails explicitly with `run:` or
`batch:` recovery guidance; history is not truncated or deleted. Large-history
latency and cancellation remain unqualified. Source-qualified filters retain
recorded Git metadata as historical selection, not proof of current source.

## Qualification

The focused Rust logs contain 256 distinct passing test names. The workspace
build, workspace Clippy, CRAP-risk gate and all ten repository gates pass.

Final sequential J127 (`native-v6`) and J263 (`native-v8`) have 105 machine
passes, zero failures, 93 capture pairs and twelve pending human judgments.
J127 has 79 passes, 72 capture pairs and eight human judgments. It completes
explicit Map/Scan selection, six fixed intercepted discovery jobs, scope
reading, two human FP decisions, export and no-color restart. Both boundaries
retain recurrence 3/3; the third remains unplanned. Shared accounting commits
six of eight calls while protecting two Review calls. Export bytes and source
remain unchanged on restart. Altered request metadata shows two known matches
and one unavailable run; restoring exact original bytes recovers three matches.
CLI and shared prepared dispatch agree. The scope menu search and Back origin
survive reading a sibling boundary.

J263 adds 26 machine passes, 21 capture pairs and four human judgments. Explicit
page waits prevent terminal Escape sequences from swallowing cancellation.
Its held invalid path survives cancellation and reopening without menu text
entering the draft. Acceptance and a fixed twelve-job plan stay separate from
execution: zero jobs and provider requests start. The original real proposal's
receipts and all nine source files remain unchanged.

Each run uses copied native binaries and source/runtime manifests, verified
before and after execution. The final runs share identical binaries and Rust
source; only J263 and its fixture changed after the successful J127. Earlier
candidates remain under `native-v1` through `native-v7`. They retain incomplete
resize captures, incorrect fixture label/wrapping assumptions, a hidden wide
Back hint and wrong generic menu help. Visual inspection of J263 v6 caught a
machine-pass case that injected menu text into the private editor; v7
overshot cancellation, and v8 adds explicit page waits and a draft assertion.

Eighteen final terminal-cell replays were inspected: fourteen from J127 across
all six scope sizes, partial/recovered metadata, Back, menu search, Report and
restart; four from corrected J263 cover the preserved draft, compact result,
unapproved plan and restart. These are ANSI cell replays, not OS screenshots,
and close no formal human judgments. Requested terminals are 40x12, 60x20,
80x24, 96x89, 120x36 and 160x48. tmux reserves one status row, so native panes
have one fewer row; focused Ratatui tests use the full requested sizes.

The transport is intercepted. Configured GPT-5.5 OAuth with medium reasoning
exercises adapter orchestration, not live inference or useful vulnerability
discovery. There are no new live requests or target-source execution. Historical
live experiments remain fourteen, with no remaining approved capacity.
Synthetic SHA unit cases prove predicate behavior only; this fixture borrows
the checkout SHA with different working source. It does not qualify a new
comparison between actual commits or show that a finding was fixed.

All nine broad milestones remain open. Formal human UX, reference parity,
larger history performance, global filtering scale and the wider module audit
remain open. New continuation cursors bind the extended query shape; reload the
first page after upgrading. Persisted findings, observations, decisions,
accepted scopes, plans and allowances are unchanged. Rust callers using
exhaustive literals must initialize the new filter/page fields or use the
existing constructors and `Default`.

Evidence root: `/tmp/kuzushi-scope-findings-20261017`.
