# Bounded filename selection for scope proposals

The saved 602-file inventory contains `workspace.json`, but the earlier scope
input omits that name from every supplied section. No shared-contract filename
fits its filename sample either, although directory counts name that group.
The model sees 496 names after the lexical-prefix and byte limits. The saved
architecture, current scope paths and operator priorities do not name the
omitted root file. This establishes an input visibility gap, not the cause of
the model's uncovered-file decision.

`pack:suggest-scopes` adds optional `fileSelection`, declared and checked by
the shared tool descriptor. `root-balanced-v1` puts loose root names first, then
takes names round-robin across sorted directory groups. Counts and samples use
the same two-level grouping. Native literal backslashes remain filename
characters on Unix. Grouping selects filename examples, not architectural
boundaries, scan scopes or jobs.

The filename list remains bounded to 512 names and 16 KiB, inside the existing
64 KiB complete input limit. It reuses saved inventory membership without
another filesystem traversal. Root and represented-directory counts accompany
omitted-name counts. Excess roots or long names can still omit material; every
unlisted member remains in coverage review. Scope output still needs explicit
operator review and acceptance, with no automatic repair or additional request.

## Existing jobs and new plans

`prefix-v1` retains the previous sample. Omission also keeps that behavior,
including the serialized filename sample. The descriptor injects no new
default into old jobs. New `campaign:context-study` scope plans explicitly freeze
`root-balanced-v1` unless the caller supplies another supported choice. Current
input validation preserves the absence of the field in existing frozen plans.
Invalid values fail preparation instead of silently choosing a policy.

The TUI names the frozen filename policy alongside the job and resource limits.
Its exact-option reader retains the machine value. New unfrozen forms describe
the new-plan default; recovered older receipts describe their recorded prefix.
Reading either plan neither approves an allowance nor starts work.

## Evidence and remaining work

The initial prepared-dispatch regression fails on the previously unknown option.
After the change, 33 scope-suggestion checks, 13 scope-study checks, 16 TUI
view-model checks and three registry consistency checks pass, 65 distinct checks.
The sampler includes an actual 100,000-entry case. The source-only controlled runtime confirms late root
and directory names in the actual request. It supplies a labeled fixed response;
this is transport/input evidence, not a model-quality result. Workspace build,
Core/TUI/CLI all-target Clippy and the changed-code risk gate pass.

The final native SHA-256 for interactive inspection is
`ac709943633ba675f25495d9521084254abe023e01ec5292caacd452ad2cae6c`.
The descriptor digest is
`sha256:f6f7d03c93c59ddf4e5822944c7fc5cc3ca6c4428acea7b5e71e16aed162086b`.
An independently reconstructed prior descriptor matches the recorded old
digest before the one-option difference is compared with actual native output.
Tool counts, maturity and phase behavior are unchanged.

The first runtime-free fixture preflight creates one new unapproved plan and
one authentic older plan with the preserved pre-option binary. Source bytes,
both plans and configuration are checked without any provider request, grant,
finding, human decision or queued execution.

Final sequential J386 has sixteen machine passes, zero failures, fifteen
authenticated text/ANSI capture pairs and all three agent questions answered
with State, Intent, Honesty and Craft. The agent result is `PASS_WITH_FINDINGS`;
raw exit 4 remains `REVIEW_REQUIRED`, and operator acceptance is false. All
6,758 recorded inputs stay unchanged during execution. Nine inspected ANSI cell
replays cover six sizes, exact options and no-color recovery. They use Menlo 15
and a chosen background, not OS screenshots.

The first passing native run exposed duplicate policy copy in the form and
embedded receipt. The final repeat removes the extra line and adds a viewport
regression. The prior run remains recorded. Long source identifiers, verbose
resource guidance and compact paging remain craft findings. Repository summary
verification is recorded separately; dirty drafts are not clean commit receipts.

Evidence is under
`scripts/devex/artifacts/scope-file-selection-current-20261026/`.
The original paid scope variant remains unchanged and unaccepted, including its
uncovered root file. Cumulative live experiments remain nineteen, with no
remaining allowance. No real-model result for the new policy is claimed.
Unfamiliar-repository grouping, complete source understanding, aggregate IO,
reference-product UX and operator acceptance remain open.
