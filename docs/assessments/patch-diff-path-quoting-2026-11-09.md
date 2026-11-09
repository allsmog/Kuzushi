# Applied-patch records named files that do not exist (2026-11-09)

## The defect

`remediation/patch/apply_reviewed_patch.rs` reads the file names a reviewed
diff touches out of the diff text, and those names are what the durable
`PatchLifecycleRecorded` event, the before/after content hashes, the
`ensure_planned_files_unchanged` guard, and the finding exports all stand on.
The reader treated the diff's two name formats as if neither had any escaping,
so two ordinary kinds of path arrived as names of files that do not exist.

**A name holding a space.** `diff --git` separates its two names with a space
and quotes neither when neither needs escaping, which is why git appends a tab
to the `---`/`+++` lines of such a file — the `diff --git` line alone is
ambiguous. The reader took the first two whitespace-separated tokens, so

```
diff --git a/my file.txt b/my file.txt
```

was read as the two paths `my` and `file.txt`.

**A name git quotes.** With the default `core.quotePath`, git wraps a name in
double quotes with C escapes whenever it holds a byte it must not emit
literally — a quote, a backslash, a control character, or any byte above ASCII.
So `src/café.rs` reaches the reader as `"a/src/caf\303\251.rs"` on every header
line, and the reader kept that text verbatim: the recorded path was
`"a/src/caf\303\251.rs"`, prefix and escapes and all.

## What that cost

- The lifecycle record names paths that were never touched, with
  `before_hash`/`after_hash` both `null` because nothing is there to hash, and
  the finding export carries those paths to whoever reads the remediation.
- `ensure_planned_files_unchanged` compares the hashes of the planned paths
  between recording intent and applying the diff. Hashing an absent path yields
  `None` both times, so for a quoted name — where *every* recorded path was
  fabricated — the guard compared nothing and could not notice that the real
  file had changed underneath the reviewed diff.
- `validate_repository_relative_path` and the `.git` guard ran on the quoted
  text, so they never saw the path they were written to judge. `git apply`'s own
  `verify_path` still refuses `..` and `.git`, so this was defense in depth that
  had stopped defending rather than a way through; the tests now pin the decoded
  reading.
- A *mode-only* diff was the worst case for a spaced name: with no `---`/`+++`
  or `rename` line to fall back on, the `diff --git` line is the only name in
  the patch, so the real file was never recorded at all.

## Why this ranked first

Ten problems were ranked this run (see the PR body). This one won because it
is reached by an ordinary filename rather than a crafted one, it silently
writes false evidence into a durable `.kuzushi` artifact that Kuzushi's whole
pitch is that an operator can trust, it empties a guard the code says it
enforces, and the fix is deterministic, model-free, and local to one parser.

## The change

`crates/kuzushi-core/src/git_quoted_path.rs` is new and owns one thing: reading
back git's `quote_c_style` form, including octal byte escapes, and refusing
malformed quoting instead of returning a half-decoded name. It sits beside
`git_rev.rs` because it is a property of git's text output, not of patching.

`apply_reviewed_patch.rs` now reads each header for what it is:

- A single-name header (`---`, `+++`, `rename from`/`to`, `copy from`/`to`)
  carries the whole rest of the line, so it decodes a quoted name and otherwise
  keeps the pre-existing tab trim.
- A `diff --git` line is split by finding the space where the `a/` and `b/`
  sides name the same path, which is how git reads it too, and the sides keep
  their prefixes so a repository that really has an `a/` directory keeps its own
  path.
- Git quotes only the side that needs it, so `diff --git "a/caf\303\251.txt"
  b/plain.txt` is a real rename header. The first quote in the line opens the
  quoted side and bounds the other.
- A rename whose unquoted names differ *and* hold spaces cannot be split at
  all. It now contributes no name from that line rather than a guess, and the
  `rename from`/`rename to` headers — which are unambiguous — supply both.

## What is not claimed

- The other places Kuzushi reads git's human-readable path output are
  untouched, and they have the same undecoded-quoting defect:
  `workspace/diff_scope/contains_path.rs` (`git diff --name-only`),
  `build_whitebox_diff_scope_report.rs` (`git diff --name-status`), and
  `status_from_name_status/diff_parsing.rs` (`parse_diff_path`, whose
  `normalize_repo_path` turns `"caf\303\251.txt"` into `caf/303/251.txt`). The
  first two are fixed by asking git for `-z` output the way
  `git_tracked_paths.rs` already does, which is a different change with a
  different blast radius; the third needs this decoder. They are named here so
  the remaining hole is visible, not left implied.
- A removed line whose content begins `-- ` reaches a line-oriented diff
  reader as `--- `, so removing the SQL comment `-- "../legacy"` puts
  `--- "../legacy"` in a hunk body. Decoding that as a name made it the path
  `../legacy` and refused a patch the prior reader accepted, so the reader now
  skips hunk bodies whole and reads names only from the header region. The
  boundary rule is `recount_hunks::hunk_body_end`, the one the canonicalizer
  that recomputed the hunk's counts already used, so both readers agree on
  where a body ends rather than each carrying a rule of its own.

  What that rule still cannot resolve is a removal immediately followed by an
  addition whose rendered lines are `--- x` then `+++ y`: that is a file-header
  pair to any line-oriented reader, and git only tells it apart by counting the
  hunk body. The ambiguity is pre-existing, shared with `recount_hunks`, and not
  resolved here.
- Nothing changes about which diffs `git apply` accepts, nor about the
  `PatchLifecycleRecorded` schema. Only the names written into it change, and
  only where they were wrong.
