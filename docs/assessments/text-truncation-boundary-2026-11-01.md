# Byte-budget truncation: three clip sites panicked on ordinary non-ASCII source (2026-11-01)

## The defect

`&text[..limit]` panics with `byte index N is not a char boundary` when the
limit lands inside a multi-byte UTF-8 character. Fourteen production sites clip
text to a fixed byte budget. Eleven had written a boundary walk of their own.
Three had written none:

1. `capabilities/systems_hunt/domain/string_array.rs::trim_line` — `&trimmed[..240]`.
   Its input is a line of scanned repository source: `gather_systems_context.rs`
   iterates `body.lines()` and records `trim_line(line)` as the evidence snippet
   for every classified line, and `hardening_signals.rs` and
   `build_surface_pack.rs` call it the same way. A source line longer than 240
   bytes whose 240th byte falls inside a character — a CJK or Cyrillic comment,
   an accented string literal, an emoji — crashed the `systems-hunt` scan.
2. `capabilities/taint_iris_next/application/codeql_build.rs::build_codeql_build_prompt`
   — `&manifest_excerpt[..6_000]`. `manifest_keywords` reads up to sixteen build
   manifests and keeps `chars().take(2_000)` of each, so the joined excerpt
   passes 6000 bytes on ordinary repositories; a non-ASCII byte at the cut
   crashed `taint-iris-next:codeql-db` before the build plan was requested.
3. `kuzushi-cli/src/adapters/auth_oauth.rs::masked_openai_base_url` —
   `&base_url[..96]`. An operator may configure any base URL, so a non-ASCII
   host or path over 96 bytes crashed `kuzushi auth` while reporting it.

None of the three is reached by hostile input only. A repository with a
non-English comment is enough, which is the normal case for the third-party
code a scanner exists to read.

## Why this ranked first

Ten problems were ranked this run (see the PR body). This one won on three
counts: it is a crash rather than a cosmetic gap, it fires on ordinary rather
than adversarial input, and it sits in three separate shipped surfaces at once
(a scan engine, a CodeQL database build, and the auth preflight) while being
deterministic, model-free, and small enough for one reviewable change.

`crates/kuzushi-core/src/panic_surface_lint.rs` is the ratchet that would
normally catch a reachable panic on externally shaped bytes, but it scans for
`unwrap`/`expect`/`panic!`/`unreachable!` in four named directories. A slicing
panic matches none of its patterns and none of these three files sits in those
directories, so the ratchet was never going to see this class.

## The change

`crates/kuzushi-core/src/text/truncate.rs` now owns the policy once:

- `floor_char_boundary(text, index)` — the largest index at or below `index`
  that `text` can be split at, mirroring the still-unstable
  `str::floor_char_boundary`.
- `utf8_prefix(text, max_bytes)` — the longest prefix fitting the budget, cut
  at a character boundary.

The three panicking sites call `utf8_prefix` and name their budget as a
documented constant. Nine sites that had each inlined the same boundary walk
now call the shared helper: `workspace/git_history_mining`,
`evidence/context/group_registry_by_kind`, `runtime_diagnostics`,
`capabilities/variant_ndiff/application/build_variant_lift_prompt` (whose
`ndiff_diff_prefix` had become a pure alias and is gone, with both callers
using `utf8_prefix` directly), `capabilities/threat_model/application/source_bundle`,
`capabilities/taint_iris_next/application/agent/agent_runtime`,
`capabilities/taint_iris_next/application/identifier_injection_detector`
(its left clamp; the right clamp has no second user and stays local), and in the
TUI `app/agent_session/ask_agent/agent_prompt` and
`app/tool_runner/.../result_receipt`.

Each of those nine was byte-identical to the shared helper before the move, so
their output is unchanged and their existing tests cover the extraction.

## What is not claimed

- `crates/kuzushi-mcp-revng/src/tools/mod.rs` keeps its own
  `floor_char_boundary`. That crate does not depend on `kuzushi-core`, and
  taking the dependency for one four-line function is not worth it.
- `workspace/domain/workspace_state_initialization/git_policy/command.rs::truncate_diagnostic`
  is left alone. Its `char_indices` walk returns the *start* index of the last
  character beginning at or before the limit, so it cuts one character earlier
  than the boundary floor. Swapping it would change operator-facing output for
  no defect, so it stays as written.
- No new ratchet or lint. A reliable static check for "integer-literal byte
  slice of a `&str`" needs type information that the existing text-scanning
  lints do not have, and the shapes it would have to allow (`&buffer[..count]`
  over a `Vec`, `&hash[..12]` over hex) would make it noisy. The three sites
  are covered by regression tests instead, each of which panics against the
  prior code.
- Nothing here changes a byte budget. Where a surface clipped at 240, 6000, or
  96 bytes, it still does.
