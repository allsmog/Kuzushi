# Child-target source evidence, October 26, 2026

License, dependency-policy and standalone secret scans could report a path
relative to a child directory while saving it in the parent workspace ledger.
When both directories contained the same filename, the observation could retain
the parent's bytes as grounded source. Native before checks reproduce that
failure for all three tools. This affects evidence identity, not just display.

The adapters now bind normalized finding paths to the explicit workspace before
persistence. The retained source belongs to the cited child file. License and
dependency SAST adapters also rebind their existing producer fingerprints when
directory paths are rewritten. Opaque secret producer fingerprints remain
compatibility aliases; the source locator and workspace path establish durable
identity. Sibling paths remain separate. Raw secret `data.findings` keeps its
engine-relative contract, while `coreFindings`, the ledger and exports use
workspace paths. Public field names and tool names are unchanged.

Relative inline targets and equivalent `target`/`cwd` values now resolve against
the explicitly selected workspace before CLI containment checks. An external
process working directory cannot change that base. Traversal outside the
workspace is still refused. License path formatting preserves literal Unix
backslashes through the shared path projection.

Eleven new prepared-dispatch contracts check real saved source, sibling
separation, direct/SAST identity and opaque secret aliases. Five CLI additions
check relative JSON, options, aliases and traversal. Together with the relevant
license, dependency and secret checks, 202 distinct focused Rust tests pass.
The earlier package-boundary and reader increment brings the combined set to
237 distinct checks. Core/CLI Clippy passes; the existing vendored terminal
parentheses warning remains visible. Early compile and fixture-setup failures
are retained separately from successful runs.

Evidence is retained under
`scripts/devex/artifacts/child-target-current-20261026/` and the standalone
secret before probe under
`scripts/devex/artifacts/secret-child-target-current-20261026/`. The first J378
binary covers license and dependency repairs: 20 machine passes, zero failures,
24 authenticated capture pairs and four answered agent screen reviews. Its
six local scans retain six observations, four findings and one scripted
deferral through JSON export and no-color restart. The raw harness exit remains
4, with a separate `PASS_WITH_FINDINGS` agent assessment. Original source cuts
and the frozen binary are preserved when extending the check to secret scans.

Final J378 `native-attempt-2` includes all three adapters. It has 22 machine
passes, zero failures, 26 authenticated text/ANSI capture pairs, two no-color
captures and four answered agent screen reviews. Nine explicit scans retain
nine observations, six findings and one scripted deferral. The unsent composer
survives three external SAST jobs. JSON export and restart preserve paths,
decisions and source references. Independent checks compare every retained blob
with the exact owned child bytes and confirm the parent's bytes were not used.
Secret raw output keeps its legacy alias while normalized output uses the child
path. No package script executes.

The final binary SHA-256 is
`401c326306a519856a09fa54eea996b959347c099af2613fb1876b1cb78266fe`.
All 6,715 recorded inputs and executable identities remain unchanged during the
run. The raw harness exit remains 4; the separate source-route assessment is
`PASS_WITH_FINDINGS`. This does not qualify complete guided phase progression.
Workspace build and Core/CLI Clippy pass for this source cut.

A separate fresh J367 run validates real Git history using an existing owned
two-commit bundle. It records two model-free scans, four observations, two
finding identities and scripted false-positive and deferred decisions. Earlier
source survives a checkout change and deliberate live-file removal. JSON,
JSONL, CSV, SARIF and the Markdown bundle retain the later observation SHA and
the earlier relationship endpoint SHA. The two commits are
`7cac9e253984e19ccc6aaeee3eb157de049ba667` and
`c557cdbf94b931ecc250b33d33d793f79036a908`. No new fixture commit is created.
J367 has 38 machine passes, zero failures, 25 capture pairs and four answered
agent screen reviews. Its setup failure from a missing fixture helper remains
recorded. Evidence is under
`scripts/devex/artifacts/sha-reader-current-20261026/`.

These checks establish source retention, comparison and export on owned
fixtures. They do not adjudicate fixes, establish detector precision, accept a
Map context, complete a guided study or prove reference-product UX parity.
Long source lines, repeated guidance, long observation references and generic
next-Map guidance on advanced child-only routes remain friction. Images used
for review are ANSI cell replays with Menlo 15 and a chosen background, not OS
screenshots. No model request or target source execution is added. Cumulative
live experiments remain at 17 with no remaining allowance.

Existing ambiguous observations and their human decisions are preserved.
Updating cannot repair the earlier saved source. Rescan the intended child,
review the new source receipt and reassess affected decisions explicitly. New
workspace-qualified paths can create new identities; old relationships require
review. A later missing finding never establishes a fix.
