# Captured source identity during human review

The source-qualified review form previously repeated the finding title and
location, but its verdict and reason steps could hide the captured revision.
At 40 columns the operator could enter a decision without seeing which SHA
and clean/dirty state it applied to. The retained two-SHA audit had already
identified weak identity context in this editor.

## Change

Every form stage keeps the finding title, cited location and captured identity
in a fixed three-row header. Paging code or the confirmation receipt leaves
that header visible. A recorded commit shows a twelve-character SHA prefix
and its recorded clean/dirty state. Full commit and content identities remain
in the source receipt. Missing Git metadata uses recorded content identity
with an explicit Git-unknown label. Missing capture and unavailable identity
remain distinct, and absent dirty metadata never becomes a clean claim.

Long paths retain the filename and line; terminal controls are escaped. The
plain reader retains its full finding-generation/location line and adds the
same captured identity. Reading preserves the reason, cursor, composer and
navigation state. It does not recapture source, change a decision, start a
scan or request a model. Existing save-time source checks remain authoritative.

The two-SHA fixture now imports a pinned 958-byte local bundle containing its
two previously retained owned commits. It no longer creates commits during
setup or depends on an expired external checkout. Both commits contain only
an ignore file, documentation and an inert public example. Their hashes are
unchanged. The smoke check verifies both clean states and the unchanged cited
file, with no network, target execution or new commits.

The first new native pair passed 89 machine checks with zero failures, but
visual inspection exposed repeated file metadata and explanatory text crowding
the cited line out of the first 40-column code frame. The code reader now uses
one compact captured-code label. The fixed header supplies location, while the
full location remains in the source receipt and plain output. The header now
explicitly labels the SHA as captured. The native check additionally requires
the actual cited line in the first 40-column frame. The earlier binary and
captures remain retained for comparison.

## Verification

All 28 distinct focused source/revision, decision and viewport checks pass,
as do the workspace build and ten repository gates. The risk proxy covers
511 changed code files. One unused selector matched no tests and receives no
credit; its three intended metadata checks are included in the six recorded
source-applicability checks.

Final sequential native J196/J199 has 90 machine passes, zero failures and
53 authenticated text/ANSI capture pairs. Seventeen unique terminal-cell
replays were inspected at all six sizes. Five human judgments for this pair
remain pending; earlier judgments elsewhere are not closed by this run.
No-color restarts are verified. These are ANSI-cell replays, not OS screenshots.

All 4566 Rust/build inputs, 802 runtime inputs and thirteen frozen programs
retain their recorded hashes through both journeys. The native binary SHA is
`0ac8cbda0c4f7cc6a6701a385ed99eac1ff1a890960ba66ce8079f6a30781872`.
The earlier 89-pass pair, binary, source differences and seventeen inspected
replays remain retained before the code-reader cleanup. Neither pair creates
new fixture or project commits, starts a model, or executes target source.

The two real fixture commits remain
`7cac9e253984e19ccc6aaeee3eb157de049ba667` and
`c557cdbf94b931ecc250b33d33d793f79036a908`. Their trees differ in documentation;
the cited public example is identical. Six actual scanner runs record three
same-source repetitions, one later-commit observation, a covered absence and
an excluded scope. Four raw observations remain. Comparison preserves seen
again, not observed and not reassessed; absence never becomes a fix. The first
human FP stays tied to its original source and requires reassessment after the
later observation.

J199 reads actual captured bytes and saves one explicitly source-qualified
deferral. The two human decisions and four raw observations survive restart.
JSON, JSONL, SARIF and Markdown exports preserve the identical reviewed-source
record, including commit, dirty state, content identity and cited object.
The object bytes match the owned cited file. Provider reservations, work
attempts and allowance revisions remain zero.

Evidence: `/tmp/kuzushi-source-identity-header-20261017`, with final binaries,
captures and verifiers under `refined/`.

## Limits

The fixture exercises deterministic source observations and explicit human
decisions. It cannot establish nondeterministic detection quality, every
scanner's source binding or operator delight. Wide forms remain sparse, and
full source identities require paging in narrow terminals. Full UX and phase/module
acceptance remain open. All nine broad milestones remain open. Historical
live usage stays fourteen with zero remaining live allowance. Publication
stays a draft on main. Exploit development, reproducer work and vulnerability
patching remain excluded.
