# Discovery scope audit, 2026-10-05

This increment audits discovery membership in the shared SAST and native scan
paths. It is a partial functionality audit, not a maturity or retirement decision.
The source is dirty work on `058388c588333466ca47846322ed38c6733dcabe`.

Native file selections previously became parent-directory jobs. Finding filters
hid that extra work. They now fail before scanner preflight; a directory must be
chosen explicitly. The resolver reuses workspace containment and symlink checks.
Reported absolute paths outside a scan root and relative parent traversal fail
instead of being converted into apparently scoped source paths. Overlapping
directory roots run once while retaining loose files in the selected parent.

Shared prepared dispatch checks membership before study compilation. Pipeline
execution checks again. Repository-wide engines cannot silently lose `paths`;
unsupported single-file or multi-directory taint input cannot become a whole
repository hunt. Explicit agentic patterns cannot replace `paths`, including
through a nonempty pattern override. No engine or model is substituted.

| Tool or engine | Scope evidence | Functional evidence in this increment | Remaining evidence |
| --- | --- | --- | --- |
| `sast:scan` | Shared preparation, native roots and delegated guards tested | Real directory-scoped secret discovery writes findings; usable native gaps retain partial observations and authenticated coverage | Fatal/cancellation/indexing retention, complete per-engine audit and all interfaces |
| `secret-scan:scan` via SAST | Directory root stays selected; files and symlink roots refused | Synthetic token fixture produces a source-located finding from the selected directory; sibling observations are absent | Deep traversal, limits, partial work, direct-tool parity and precision |
| `dep-hygiene:check` via SAST | Directory-root adapter source reviewed | No real engine exercise in this increment | Nonempty phase consumption, coverage gaps, dependencies and resources |
| `cargo-audit:scan` via SAST | Directory-root command; file scope refused | No real engine exercise in this increment | Root-only prerequisite check must account for selected directory; bounded availability probe |
| `govulncheck:scan` via SAST | Directory-root command; file scope refused | No real engine exercise in this increment | Dependency graph coverage, cancellation and consumable output |
| `license-scan:scan` via SAST | Directory-root implementation; file scope refused | No real engine exercise in this increment | Source coverage, filtering, partial work and consumable output |
| `iac-scan:scan` via SAST | Directory-root implementation; file scope refused | No real engine exercise in this increment | Deep traversal, coverage gaps, limits and consumable output |
| `semgrep:scan` via SAST | Directory-root command; file scope refused | Installed Semgrep retains one local-rule observation alongside an incompatible-rule report through the repaired trait adapter | Default rule usefulness/precision, direct-module persistence parity, fatal errors, cancellation and exact-file support |
| `codeql:scan` via SAST | Directory-root dispatch and normalization integration passes | Existing runner integration passes | Reused database/source membership, coverage, subprocess limits and real engine output |
| `agentic-sast:scan` via SAST | Membership validation and derived inventory-pattern tests; explicit overrides refused | No model execution in this increment | Read-tool/MCP access isolation, inventory omissions, strategy options and actual discovery quality |
| `taint-iris-next:hunt` via SAST | One directory with matching subdir allowed; files, multiple paths and conflicts refused | Preparation tests only | Actual catalog/hunt boundary, context and MCP source membership |
| `offense-review:threat-hunt` via SAST | Scoped jobs refused; whole-repository preparation remains available | Preparation tests only | Bounded repository-wide discovery, consumable evidence and cost |
| `systems-hunt:systems-hunt` via SAST | Scoped jobs refused; whole-repository preparation remains available | Preparation tests only | Bounded repository-wide discovery, consumable evidence and cost |

The real native fixture runs source analysis only. A synthetic token is present
in both directories and the selected-directory result is persisted through the
real shared dispatcher. It does not measure scanner precision or live model
quality. Findings being absent in a sibling scope does not prove it was unread;
the selected-root adapter and containment evidence provide that boundary proof.

J77 at `/tmp/kuzushi-bounded-investigations-tui/20261005-083800/J77/` has 19
machine passes and nine separately recorded screen passes. The TUI rejects a
file, explains the directory tradeoff, lets the operator revise it and prepares
three fixed jobs with one worker. No allowance approval, scan job or provider
request occurs. Six sizes, paging at 40x12, actual exit and no-color restart
are captured with hashes and dimensions in `manual-review.json`. Raw
REVIEW_REQUIRED is unchanged. The earlier `082413/J77` failure and its separate
judgments preserve the recipe's over-paging and incorrect exit expectation.
Final-build captures match the preceding manually reviewed `082659/J77` frames
byte for byte; their separate receipt records fresh provenance and hashes.

Focused evidence is under `.git/bounded-investigations/`: eight guard tests,
ten existing/native runner tests, five path tests, six delegated adapter
tests and three context/source-drift regressions. Scope preparation assesses
declared contracts without subprocess availability probes, keeping TUI draft
preparation responsive. The initial path-test failure compared a macOS temporary-path alias to
its canonical path; the repaired test checks the canonical root. Workspace
build and CRAP-risk pass. All ten quick gates pass in
`.git/bounded-investigations/scope-final-verification.json`, finished
2026-10-05T15:38:45.544Z. This is a dirty working-tree receipt and excludes the
full CI matrix. Later documentation closeout is recorded separately.

Scope-tree editing, AI proposals and finite monorepo execution remain unfinished.
The current failure route returns to scanner options; it does not yet provide
the first-class scope editor required by the product plan. No module was deleted
or promoted, and no full end-to-end or reference-interaction parity claim follows.

The subsequent [native partial-coverage audit](./native-partial-coverage-2026-10-05.md)
separates typed-runner tests, real scanner output and terminal judgments. An
unreadable source file fails source identity capture before discovery; it cannot
be credited as a usable permission-gap scan. Semgrep recovered the malformed
test input without a reported parser error. The real partial exercise uses an
explicit incompatible rule instead. This is retention and workflow evidence,
not an engine-quality or complete-coverage certification.
