# Lesson reports and recorded scan completion

The external scanner export previously wrote `scan_completed: true` for every
export, including workspace history without a selected scan plan. An actual J120
file reproduced this claim with zero campaign plans. The focused workspace-history
regression failed before the repair with `true` where `false` was expected.

The renderer now starts with unverified completion. The shared receipt attachment
used by export and preview sets the flag to true only for an authenticated selected
study with nonzero planned work, all jobs completed and no pending or failed jobs.
The file shape, finding rows, lessons and decisions remain unchanged. Re-exporting
older files obtains the corrected value. `RELEASING.md` and `docs/modules.md`
describe the correction and its limited meaning: finished planned work does not
establish complete repository coverage or a fix.

## Lesson export qualification

J120 now retains draft, accepted, rejected and retired lessons through all six
Report export formats and no-color restart. JSON, JSONL, SARIF and Markdown bundle
checks compare each complete lesson and exact revision reference. Markdown's
indented JSON keeps Unicode and literal backticks inert. Only the accepted lesson
is eligible for future context. CSV and the external scanner format disclose
omissions before export; their files do not contain lesson text.

The fixture uses real ledger and prepared tool dispatch with scripted synthetic
records. Its SQLite inspection permits WAL sidecar creation while prohibiting
SQL writes with `query_only`. This repairs the initial setup failure. The journey
also uses the current compact Report, explicit `p details`, pinned format labels
and restored format rather than outdated screen expectations. No production
Report layout or input behavior changes in this increment.

## Verification

- Seventy-four export checks pass, including the reproduced regression. Pending,
  partial, failed, empty and completed work counts are exercised, alongside
  shared prepared dispatch and preview for an unstarted study.
- Twenty-two investigation checks pass. One existing fixture producer remains
  explicitly ignored because it only runs when requested for a native journey.
- Twenty-two lesson TUI checks pass, including one owned-fixture helper. The
  workspace build, Core Clippy and risk gate pass. Two production files are scored.
- Final J120 records 29 machine passes, zero failures and 28 capture pairs across
  all six sizes and no-color restart. Fourteen ANSI cell replays were inspected.
  Seven human UX judgments remain pending. These are terminal-cell renderings,
  not OS screenshots or operator approval.

Independent artifact checks authenticate capture hashes, dimensions and the
frozen executable; compare exported lesson records; and verify every Markdown
bundle manifest digest. They retain one original observation, one original
scripted human finding decision, zero rekeys and zero model reservations,
attempts or allowance revisions. Source and active context remain unchanged.
Restart restores the external format and permits returning to JSON without work.

Evidence root: `/tmp/kuzushi-lesson-report-acceptance-20261018`.
Final run: `native-v4/native/J120/20261018-051014/J120`.
Native SHA-256:
`cb38083f75f62ce5c65eea75333905b8f2355c44c46a41a7dfce23e5a1e82107`.
Fourteen frozen programs, 4,638 source inputs and 813 runtime inputs are
authenticated before and after execution. `native-v4/independent-check.json`
records the file and ledger checks. Earlier setup/matcher failures and the
pre-repair export remain intact.

No live request, target-source execution, project commit or push is added.
Fourteen earlier live experiment requests remain spent. General model usefulness,
large-history behavior, platform qualification and full UX acceptance remain open.
Four delivery items remain locally verified and five remain open. This increment
is a draft on main after `2b31d9267d`.
