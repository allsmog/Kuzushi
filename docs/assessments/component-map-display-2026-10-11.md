# Recorded components and Map reading

A verified imported context with one component and no flows was accepted in
J219 but hidden by Map's display predicate. Display reused the stronger
architecture-completion threshold. The project context receipt also compared
status text against one label, making accepted and awaiting-review contexts
appear missing.

Display now recognizes a named component with an identity, excluding generated
scope placeholders. Summary and DFD retain its source description, purpose and
linked context, while stating that relationships remain unknown. The existing
Map completion, verification and acceptance predicates are unchanged. A stored
threat claim does not make a placeholder into a component.

Document availability is explicit and separate from its status. The project
receipt labels zero-flow topology `components only`; unavailable or malformed
context still reports absence honestly. Existing accepted-context references
remain the source for these projections.

Native testing exposed a second defect: at 40x12, navigation chrome left one
document row, and subsequent paging could show an empty body. Compact idle Map
now reserves reading space, keeps the source description visible and exposes
short paging/open controls. Drafts, active work and pending decisions retain
their normal controls. Shared Review reading behavior remains covered.

Focused tests cover display/completion separation, placeholders, exact context
availability, plain output, six widget sizes, full-shell 40x12 reading, drafts
and approval ownership. Native J220 uses only an owned README and inert
lockfile, imports manual source context, accepts Map, reads Summary and linked
DFD context, activates another context through shared headless dispatch, and
restarts without color. It creates no discovery jobs or provider requests.

Predecessor receipts remain intact under
`/tmp/kuzushi-component-map-20261012`. The first exposed compact layout and used
a relative headless path. The second expected the notice one page too early.
The third matched a phrase across inspector wrapping. Assertions now wait for
actual topology state and separate reading pages.

Final sequential J220 is
`/tmp/kuzushi-component-map-20261012/complete-tui/20261011-233925/J220`.
It has 33 machine passes, zero failures and 21 authenticated text/ANSI captures
at six sizes, including no-color restart. The frozen native binary is
`/tmp/kuzushi-component-map-20261012/native/kuzushi`, SHA-256
`0607b37adfeb1336b075db5d72f0f00a69b9997038b3b9baabab768770533217`.
Source hashes remain unchanged; provider reservations, discovery attempts,
observations and human decisions remain zero. The alternate context stays
active while the accepted Map displays its original exact revision.

Four visual judgments retain raw REVIEW_REQUIRED. Assistant capture inspection
is separate from operator acceptance. At 40x12, pages reach the full purpose
text. At 60x20 and 80x24, lower content requires scrolling; complete native
reading there is not separately captured. A preceding 32-pass run remains
preserved and is superseded only for complete narrow purpose reading.

Thirteen core Map-evidence tests, 73 DFD tests, 14 project-model tests, eight
exact-context tests, three compact Map tests, ten compact Review regressions,
18 chrome tests and 33 component-filter tests pass. Some filters overlap.
The locked workspace build and all ten repository summary gates pass.
Risk checks pass for 422 changed production files. The receipt at
`/tmp/kuzushi-component-map-20261012/final-verification.json` is dirty and
drifted, remains unsigned and predates final evidence documentation.

This increment does not qualify complete architecture coverage,
generated-context usefulness, all-terminal behavior or visual parity with
reference TUIs. Human acceptance and all nine broad implementation milestones
remain open.
