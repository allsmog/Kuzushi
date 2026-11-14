# Changed-file scope silently drops names git quotes (2026-11-14)

## The defect

Two readers asked git for `diff --name-only` and parsed its *human-readable*
output as newline-separated text. That output is not a list of paths. With the default `core.quotePath`, git wraps a name in double quotes
with C escapes whenever it holds a byte it must not emit literally — a quote,
a backslash, a control character, or any byte above ASCII — so `src/café.rs`
is printed as

```
"src/caf\303\251.rs"
```

Two ordinary kinds of name therefore arrived as the name of a file that does
not exist:

- **A name git quotes.** Both readers kept the printed text verbatim, quotes
  and escapes and all, so `src/café.rs` became the path
  `"src/caf\303\251.rs"`. A name holding a newline, a tab, a double quote or
  a backslash is the same case: git quotes those whatever `core.quotePath` is
  set to, so `line⏎break.c` arrives as `"line\nbreak.c"`. A target with
  `core.quotePath=false` escapes only the non-ASCII half of this — git still
  quotes control characters — and Kuzushi never sets that option, so the
  default quoting is what both readers met.
- **A name ending or beginning with a space.** Git does *not* quote one, and
  `git_diff_files` mapped `str::trim` over every record, so a file named
  `trailing.rs ` was read as `trailing.rs`. This one is wrong regardless of
  `core.quotePath`, and it is specific to that reader: `changed_files_since`
  trimmed only to test a record for emptiness and kept the record itself
  intact.

## What that cost

- `workspace/diff_scope/contains_path.rs::git_diff_files` is the scope behind
  `kuzushi scan --since <ref>` and the shell's `since <ref>`.
  `workspace/application/changed_scan_scope.rs::retain_existing_files` then
  drops every path that is not a file, for the good reason that a scanner
  cannot open a deleted path and writing it into a scope file only
  manufactures phantom coverage. A fabricated name is not a file either, so
  the changed file was **silently removed from the scan scope** — no warning,
  no count, nothing in the output disclosing the drop. A scan whose changed
  files were all named this way reported "nothing to scan".
- `workspace/git_history_mining.rs::changed_files_since` is the threat-model
  refine delta. `capabilities/threat_model/application/staged/refine.rs::refine_changed_surfaces`
  keeps a surface when `changed.contains(&surface.path)` — string equality — so
  a fabricated name matched no surface and the changed attack surface was
  **excluded from the refine**.

Both are silent narrowing of what a security scanner looks at, which is the
failure mode a SAST tool can least afford: the run still reports success.

## Why this ranked first

Ten problems were ranked this run (see the PR body). This one won because it
is reached by an ordinary filename rather than a crafted one, the consequence
is a false negative in the product's core promise rather than a cosmetic
label, both failures are completely silent, the repository already names this
hole in `docs/assessments/patch-diff-path-quoting-2026-11-09.md`, and the fix
is deterministic, model-free and local to one shared reader.

## The change

`crates/kuzushi-core/src/git_nul_paths.rs` is new and owns one thing: reading
git's NUL-framed (`-z`) path output. It checks the framing, requires UTF-8 and
splits on NUL, dropping empty records. It sits beside `git_quoted_path.rs`
because both are properties of git's text output, and its module doc records
the division between them: `-z` removes the quoting, and `git_quoted_path` is
for the names that only exist inside diff text, where the quoting is part of
the format and `-z` does not reach.

Both readers now pass `-z` and go through that helper. The repository already
had two `-z` readers — `workspace/coverage_ledger/sweep/git.rs` and
`capabilities/chrome_rce/adapters/git_diff.rs` — so this is the existing house
pattern rather than a new one.

A non-UTF-8 name is an error rather than a lossy replacement, because a path
holding U+FFFD names a different file than the one git reported, and scanning
the wrong file is the defect this change exists to prevent.
`git_diff_files` surfaces that error, matching the `diff_scope:` error it
already raised for non-UTF-8 output. `changed_files_since` reports it as
`Ok(None)` — "delta unknown" — because its documented contract is that a
caller seeing `Some(_)` treats every absent path as unchanged, so a partial
delta would silently exclude surfaces the same way the defect did. `None` is
not swallowed: `emit_refine_delta` prints the changed-file count as `unknown`,
so an operator sees that the delta was not resolved.

The NUL-framing check is defense in depth, not the thing catching a real
truncation: `bounded_subprocess::drain_bounded` already fails when a
subprocess exceeds its capture limit, so a half-written final record does not
reach the parser today. The check pins that, and matches
`chrome_rce::parse_changed_paths`, which asserts the same framing.

## What is not claimed

- **The whitebox diff-scope report is not fixed here.** Its two readers have
  the same defect and have to change together:
  `build_whitebox_diff_scope_report.rs` reads `git diff --name-status`
  (quoted, same hole), and
  `status_from_name_status/diff_parsing.rs::parse_diff_path` reads the
  `---`/`+++` headers of the unified diff through `normalize_repo_path`, whose
  `path.trim_matches('"').replace('\\', "/")` turns `"src/caf\303\251.rs"` into
  `src/caf/303/251.rs`. Those two keyed the same `BTreeMap<String,
  ChangedFile>`, so fixing only the `--name-status` side would make one file
  appear twice in `changed_files` — once with the real path and no line
  ranges, once with the mangled path carrying the ranges. `--name-status -z`
  frames its records as `M\0path\0` and a rename as `R100\0old\0new\0`, and the
  unified-diff header reader needs `git_quoted_path` rather than `-z`, so that
  change has a different shape and blast radius than this one. It is named here
  so the remaining hole stays visible.
- `parse_unified_diff_ranges` reads a `--- `/`+++ ` line from anywhere in the
  diff, including inside a hunk body, so with `--unified=0` a removed line
  whose content begins `-- ` renders as `--- ` and is read as a file header.
  That is the same pre-existing ambiguity recorded in
  `patch-diff-path-quoting-2026-11-09.md`, where the patch reader resolved it
  by skipping hunk bodies via `recount_hunks::hunk_body_end`. This change does
  not touch that reader.
- `coverage_ledger/sweep/git.rs::paths` and
  `chrome_rce/adapters/git_diff.rs::parse_changed_paths` already read `-z`
  correctly and are left alone. They carry extra local policy — a byte budget
  and a traversal guard respectively — and have no defect to fix, so migrating
  them onto the shared helper would be a cosmetic change to a correct path.
- Nothing changes about which files git reports as changed, nor about the
  `DiffScope` or `ChangedScanScope` shapes. Only the names written into them
  change, and only where they were wrong.
