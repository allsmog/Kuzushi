# Unanchored path-suffix matching claimed the wrong file in two shipped surfaces (2026-11-06)

## The defect

Two call sites decided "is this reported path the file I am asking about?" with
a bidirectional `str::ends_with`:

```rust
file_path.ends_with(f.as_str()) || f.ends_with(file_path)
```

A raw string suffix is not a path suffix. `src/notauth.rs` ends with `auth.rs`,
so both sites answered yes for two files that share nothing but a name ending.
Neither site is reached by hostile input only: a repository with `auth.rs` and
`notauth.rs`, or `handler.rs` and `apihandler.rs`, is enough.

1. `findings/presentation/pr_comment/build_pr_comment.rs::in_changed` decides
   which findings go in the PR comment's `New in this PR` section and the
   `🆕 N new in this PR` count that leads it. `kuzushi pr-comment
   --changed-files …` is the CI surface behind that comment (see
   `.github/workflows/kuzushi-reference.yml`), so a wrong yes credited the pull
   request with a finding in a file it never touched — in the one artifact a
   reviewer reads to decide what the PR introduced.
2. `evidence/context/match_registry_for.rs::node_within_window` filters the
   static-evidence subgraph down to nodes belonging to the finding's own file.
   Nodes that survive are assembled by `assemble_static_context` into the
   finding's `Pre-populated Static Evidence` block, which is handed to the
   triage model. A wrong yes attached another file's source, sink, sanitizer and
   guard nodes to the finding as its own evidence, within the
   `SUBGRAPH_LINE_WINDOW` line window, and the model then reasoned over it.

The repository already had the correct reading in a third site:
`capabilities/carlini_threat_hunt/adapters/output.rs` compares
`source_path == relative || source_path.ends_with(&format!("/{relative}"))` —
anchored at the separator. The policy existed; it was just not shared.

## Why this ranked first

The tolerance the two sites were reaching for is real. A scanner run against
`app/` reports `src/main.rs` while `git diff --name-only` on the enclosing
repository reports `app/src/main.rs`, so a caller does have to accept one path
being a trailing part of the other. The fix is not to drop that tolerance but to
require the trailing part to begin at a separator, which keeps every intended
match and removes the unintended ones.

It ranked above the other nine candidates because it is a correctness defect in
two already-shipped surfaces at once, both of which present their answer as
fact (a count in a posted comment; a block labelled as the finding's evidence);
because it is deterministic and model-free, so it is fully testable off-screen;
and because the shared policy is small enough to review in one sitting.

## What changed

`findings/domain/reported_source_path.rs` — which already owns reported-path
policy and already documents that a reported path is literal data — gains
`reported_paths_name_same_file`. Both call sites now ask it.

The helper compares paths byte for byte apart from the segment-boundary
allowance. `/` is the only separator it reads, for the reason
`normalize_reported_source_path` keeps `a\b.rs` literal: `\` is an ordinary
filename byte on Unix and detectors preserve it verbatim, so splitting on it
would equate two different files.

## What is not claimed

- A segment-anchored suffix is still a suffix. `src/auth.rs` and
  `vendor/src/auth.rs` are accepted as one file, because a caller holding two
  paths against unknown roots cannot tell them apart. Narrowing that would need
  the roots themselves, which neither call site has.
- `node_within_window` previously admitted a node whose recorded
  `source_path` was present but empty, because every string ends with `""`.
  It is now excluded: a path that names no file is not the finding's file. A
  node with no `source_path` at all is still kept, as before.
- Nothing here addresses `pr_comment::chain_step_location`, which renders
  `start_line.max(1)` and so reports line 1 for an exploit-chain step whose
  detector gave no line — the defect `report:sarif` had before #358. Same class,
  different policy; left for its own change.
