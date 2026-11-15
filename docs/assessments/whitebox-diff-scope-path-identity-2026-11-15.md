# The whitebox diff-scope report fabricated the paths it changed (2026-11-15)

## The defect

`workspace/diff_scope/build_whitebox_diff_scope_report.rs` builds the
`whitebox-diff-scope.json` artifact behind whitebox-static PR mode: the changed
files of a pull request, their changed and deleted line ranges, the caller and
route context around them, and the New / Existing / ChangedContext / NotSeen tag
on every finding. It reads two git outputs and keyed both by path into one
`BTreeMap<String, ChangedFile>`. Neither reader could spell a name git does not
print literally.

- **`git diff --name-status`** prints a quoted name whenever it holds a byte it
  must not emit literally — a double quote, a backslash, a control character,
  or (with the default `core.quotePath`) any byte above ASCII. `parse_name_status`
  split the human-readable output on tabs and passed each field through
  `normalize_repo_path`, which was `path.trim_matches('"').replace('\\', "/")`.
  That turns `"caf\303\251.rs"` into `caf/303/251.rs`: three directories and a
  file, none of which exist.
- **The unified diff's `---`/`+++` headers** carry the same quoting, and the
  `a/`/`b/` prefix is *inside* the quotes, so `parse_diff_path`'s
  `strip_prefix("a/")` missed it and the same `normalize_repo_path` produced
  `b/caf/303/251.rs` — a different fabricated name than the first reader's.
  A name ending in whitespace is the other half: git appends a tab terminator
  (it writes one after a quoted name too), and `parse_diff_path` ran
  `str::trim` over the line, so `trail ` arrived as `trail` while
  `--name-status`, which is tab-delimited, kept the space.

The two readers therefore disagreed about the name of the same file, and the
map they shared recorded both.

## What that cost

Against a real repository changing three files — `café.rs`, a rename to
`newï.rs`, and `trail ` — the report named five:

```
["b/caf/303/251.rs", "caf/303/251.rs", "new/303/257.rs", "trail", "trail "]
```

- `summary.changed_files` said **5**, and three of the five rows name no file.
- The file carrying the ranges and the file carrying the status were different
  rows, so neither was complete: one had `status: modified` and no ranges, the
  other had the ranges and `status: unknown`.
- `finding_tags.rs::tag_current_finding` matches a finding to a changed file by
  string equality on the path. No row equalled `café.rs`, so a finding on the
  line the pull request had just introduced was reported as
  **`existing` — "finding is outside changed files"**. That is the one judgement
  this artifact exists to make, and it was inverted: a vulnerability the diff
  added read as pre-existing.
- `tag_not_seen_findings` matches the same way, so a previous finding whose
  source was deleted by the diff was never marked `not-seen`.
- `source_context.rs::changed_source_lines` opens `root.join(&file.path)` and
  returns `None` when the read fails, so every caller and callee context for
  the file was silently absent, as was any attack-surface route on it.

All of it silent: the report is marked `deterministic: true` and the run
succeeds.

## Why this ranked first

Ten problems were ranked this run (the PR body lists them). This one won on
four counts: the consequence is a **false label on the product's core
judgement** rather than a cosmetic defect; it is reached by an ordinary
filename — any accented or non-Latin name, which is routine in i18n fixtures
and in non-English codebases — not a crafted one; it is completely silent, with
an inflated count the only visible trace; and the repository already named it
as the open half of PR #374, in
`docs/assessments/diff-scope-name-only-quoting-2026-11-14.md`. The fix is
deterministic, model-free, and confined to one module with helpers that already
exist.

## The change

Both readers now read the name git actually reported, using the two helpers the
repository already has:

- `parse_name_status` takes `git diff --name-status -z` and reads it through
  `git_nul_paths::nul_separated_paths`. `-z` prints raw bytes and quotes
  nothing, so there is nothing to decode. Its records are a status code, the
  path, and for a rename or a copy the old path before the new one;
  `changed_file_record` consumes exactly those and **errors** on an entry
  truncated after its status code rather than dropping the file, because this
  list is the whole of what the pull request changed.
- `parse_diff_path` decodes the header name with
  `git_quoted_path::take_quoted_path` and strips `a/`/`b/` *after* decoding,
  since git quotes the prefixed name as a unit. It removes git's single trailing
  tab terminator and nothing else, so a name's own trailing space survives.
- `normalize_repo_path` is deleted. Its `replace('\\', "/")` had no upside — git
  always prints `/` as the separator in diff paths — and its two behaviors were
  exactly the two ways the names were corrupted.

`parse_unified_diff_ranges` also now reads `---`/`+++` only inside the file
header, between a `diff --git` line and that file's first hunk, which is the
only place git writes them. This is required by the change rather than
incidental to it: with `--unified=0` a removed source line beginning `-- `
renders as `--- ` and an added line beginning `++ ` renders as `+++ `, so the
previous reader re-pointed itself at whatever that line of source spelled and
attributed the following hunk's ranges to it. Decoding is also stricter than
trimming — malformed quoting is an error, by `take_quoted_path`'s existing
contract — so without the header gate an ordinary SQL or Markdown line such as
`-- "note` would have failed the whole report. The gate closes the
mis-attribution and makes the error honest at the same time; it is the
third problem PR #374 left open.

The function was split into a `DiffCursor` that reads one line and
`record_hunk_span`/`push_range` that record one hunk, because adding the header
state to the existing single loop would have left one function holding both the
line grammar and the range arithmetic.

## What is not claimed

- **A non-UTF-8 filename is now an error instead of a fabricated path.** Both
  helpers refuse one, by the contract they already documented: a path holding
  U+FFFD names a different file than git reported, and the report would be
  attributing findings to it. Such a name previously produced a row that
  matched no finding and no file on disk, so nothing that used to resolve
  stops resolving — the failure becomes visible instead of silent.
- **Nothing changes for an all-ASCII, unquoted name.** `-z` is byte-identical
  to the tab-delimited output for those, and `parse_diff_path` returns the same
  string it did before. Every pre-existing diff-scope test passes unchanged,
  including `whitebox_diff_scope_computes_ranges_context_and_finding_tags`.
- **The report's schema is untouched.** `ChangedFile`, `DiffScopeSummary`,
  `whitebox-diff-scope.json` and its field names are the same; only the names
  written into them change, and only where they were wrong.
- **`parse_unified_diff_ranges` still trusts `--find-renames` for the rename
  pairing it gets from `--name-status`.** A rename with no content change emits
  no hunk, so its ranges come from nowhere; that is git's output, not a reader
  defect.
- **The `previous_path` fallback in `record_hunk_span` is now unreachable in
  practice.** `--name-status` lists every file in the diff, so the hunk reader
  no longer creates entries; it kept that branch because the two readers are
  separate git invocations and neither should assume the other succeeded.
