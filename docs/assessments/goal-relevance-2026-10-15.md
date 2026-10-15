# Goal relevance in Review

The [subsequent reader integration](review-reader-controls-2026-10-15.md) keeps
`G` for finding groups and moves goal relevance to `O`. The original captures
below used the earlier conflicting `G` binding and remain historical evidence.

Operators can now assess and browse relevance to an exact saved investigation
brief. This fills the missing goal-relevance surface in the bounded plan.
It does not supply finding validity, confidence, severity or Review completion.

`findings:goals` reads a published brief and the authoritative workspace finding
set. It sorts Direct, Related, Unassessed, Uncertain and Outside goal separately
from the normal Review order. Fifty-row shell pages, category filters, exact
brief reading and observation receipts are visible in the browser. The ordinary
finding filter and selected study are not inherited. The source basis is the
recorded generation, event, run and snapshot, with recorded commit metadata when
available. This action does not reassess the current checkout.

`findings:goal-assess` consumes that exact basis and published brief reference.
The shared writer compares the observation and assessment revision before
appending one diagnostic record. Clears append history. The reviewed goal text
and exact reference stay in each record; a later brief revision starts with no
assessments. A changed finding observation does not acquire a prior assessment.
Normal finding verdicts and confidence remain independent.

The shell browser opens with `goals [brief-id]` or `G` in Review navigation.
Reason editing owns paste and multiline input. Ctrl+S opens explicit replacement
review, including the previous reason; Enter saves. Back, target switches and
brief switches retain the draft in the running shell. A conflicting write keeps
the reason. Refresh and explicitly reselect the assessment before reviewing its
replacement. `h` reads recorded history. Quit names unsaved reasons without
printing them. Unsaved assessment forms are session-only, not crash checkpoints.
Background completions never open the browser or change the underlying page.

JSON/JSONL, SARIF, Markdown bundles and external finding exports carry the
history separately from verdicts. CSV explicitly discloses its omission. Rebuild
replays the existing diagnostic audit events; no parallel findings ledger or
orchestrator was introduced. The tools declare runtime-free Review policy and
cannot create model requests, study jobs, allowances or phase-completion results.

## Verification scope

Seven focused core checks cover reversible assessment, exact old briefs,
pagination/filtering, invalid references and inputs, concurrent compare-and-append,
changed source observations, export and projection rebuild. Two TUI behavior
checks cover the viewport matrix, reason/composer preservation, retained drafts
across brief changes, Quit disclosure, hidden completion and save/clear behavior.
The separate native fixture setup test creates three explicitly labeled policy
observations; it is not a vulnerability detection test.

The locked workspace build and risk proxy pass. Native J274 uses an immutable
13-executable bundle and the owned policy fixture. Its first attempt is retained:
a save check matched pending confirmation text, and a rapid double-Escape did
not finish the return sequence. The final implementation adds a distinct save
receipt, and the journey waits for each real transition. No model requests,
target source execution or finding verdict writes are authorized by this test.

The final J274 run records 46 machine passes, zero failures and 36 live
text/ANSI capture pairs. Its three human judgments remain pending. The native
SHA-256 is `bebc06042db4ee7456e1ee9047bfcd1791d69d6e48fa21dec50db0ded212f548`.
Thirteen executables are immutable; 57 Rust input files stayed identical across
the final tests and locked workspace build and remain identical at capture review.
The run exercises both `G` entry and typed `goals` after restart, explicit
conflict replacement, all four retained revisions, clearing, frozen/updated
briefs and unchanged observations/decisions/accounting. The restarted ANSI
capture contains no color SGR parameters. Selected captured layouts and state
transitions were inspected separately from machine assertions.

Capture review also replaced long internal identifiers in primary feedback,
formatted UTC times and separated the wide list/detail columns. The forty-column
reason and confirmation captures keep the source path and controls visible.
One intermediate layout run caught an earlier reason heading still present in
its binary after source edits during compilation. Its after-build source hash
manifest is explicitly disqualified as proof of full source equivalence. The
replacement records and compares source bytes before and after validation; no
Rust edits occur during that run. Rapid Escape sequences remain unqualified;
the final journey waits for each real navigation state.

Evidence root: `/tmp/kuzushi-tui-integration-20261012`.
Final run: `goal-review-stable-tui/20261015-003038/J274`.
Current hashes, runtime identity and assistant review scope:
`goal-review-stable-assistant-review.json`.
Stable build inputs: `goal-review-stable-source-before.json` and
`goal-review-stable-source-after.json`.
Earlier failed and passing runs retain their own captures and journey sources.


Machine state checks do not approve the journey's human judgments or establish
reference-product parity, operator delight, hardware latency, large-history
performance, the full Rust suite or CI/platform qualification. All broad plan
milestones remain open. The eight-request live allowance remains exhausted;
the separate six-request Scan proposal is still unanswered.
