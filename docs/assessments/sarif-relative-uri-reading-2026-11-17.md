# SARIF relative `artifactLocation.uri` reading — 2026-11-17

## The defect

SARIF 2.1.0 §3.4.3 requires `artifactLocation.uri` to hold a URI reference, so a
file name carrying any byte outside the RFC 3986 unreserved set arrives
percent-encoded — whether the reference is relative or absolute. Kuzushi's own
emitter says so in its own doc comment and does exactly that:
`findings/presentation/sarif_location.rs::relative_uri_reference` turns
`docs/My Notes.md` into `docs/My%20Notes.md`, and its test asserts that form.

The readers of another engine's SARIF did not read it back:

- `scan/engines/codeql/map_severity.rs::normalize_artifact_uri` percent-decoded
  only after a successful `strip_prefix("file://")`. A relative reference — what
  `codeql database analyze` writes for every result in the analyzed source tree
  — passed through encoded. Both of `extract_location.rs`'s readers used it: the
  one that produces `Finding.file_path` and the one that produces each code-flow
  step.
- `capabilities/taint_iris_next/application/codeql_dataflow.rs::sarif_location_to_step`
  did no decoding at all and had no `file://` handling either. Its value becomes
  `CodeqlFlow.file_path`, then `TaintIrisNextLinkedStory.file_path` and the
  `source_candidate_id` / `sink_candidate_id` built from it.

So a CodeQL finding on `src/café/My Query.rs` was reported at
`src/caf%C3%A9/My%20Query.rs`, and the two new regression tests print exactly
those strings against the prior code. That name names no file:

- nothing can open it to triage, verify, or patch the finding;
- `reported_paths_name_same_file` matches neither the name git reports for the
  file (so `scan --since <ref>` tags the finding as outside the changed files)
  nor a path-scoped suppression naming it;
- re-exporting the finding encodes the escapes again
  (`src/caf%25C3%25A9/My%2520Query.rs`), so the SARIF handed to GitHub code
  scanning anchors nowhere;
- `Finding::new_tool` derives the fingerprint and the dedup key from
  `file_path`, so the finding's durable identity was derived from the fabricated
  name.

Two smaller readings in the same helper were wrong in the same direction:

- `\` was normalized to `/` *after* decoding, so `%5C` — which
  `relative_uri_reference` emits precisely because `\` is an ordinary filename
  byte on Unix, and whose comment ends "`%5C` is reversible; a wrong split is
  not" — was split into a separator.
- `percent_decode` ended in `String::from_utf8_lossy`, so a name that does not
  decode to UTF-8 became U+FFFD: a different file than the one the engine found.

## Why it ranked first

It is a false-negative-shaped defect in the scanner's primary output, on a
surface Kuzushi already documents the contract for in the opposite direction, and
it is reachable with no unusual configuration: a space in a source file name is
enough. The fix is one shared helper, the inverse of an encoder that already
exists in this repository, and the two existing copies of the reading were
already drifting apart from each other.

## What changed

`reported_path_from_sarif_uri` lives beside the encoder it inverts in
`findings/presentation/sarif_location.rs`, and inverts all three branches of
`sarif_artifact_location`: a non-file URI scheme reads back verbatim, an
absolute `file://` URI reads back relative to the root it names, and a relative
reference is percent-decoded. A literal `\` is normalized before decoding and an
escaped one is not. `%2F` still decodes to a separator: no path segment on a
supported platform can hold `/`, so an escaped one is only ever a separator its
producer escaped.

`normalize_artifact_uri` and `percent_decode` are deleted, as is the
`hex_value` the latter was the only consumer of. All three call sites in
`kuzushi-core` use the shared helper.

`extract_codeql_flow_steps` grew a fourth branch from the new skip and was split
to pass the risk gate: `thread_flow_steps` flattens the three nested loops, and
`thread_flow_step` builds one step from one thread-flow location. The uri, line
and snippet readings `location_path_and_line` and the step builder had in common
are now three named helpers instead of two copies.

## What this does not claim

- **Behavior change, deliberately fail-closed.** A reference that does not
  decode to UTF-8 is now `None`, so the location is skipped. The engine already
  discloses that as "CodeQL SARIF omitted N result(s) without a usable physical
  location", and the compatibility `normalize_codeql_sarif` turns any such
  omission into an error, so a scan over a non-UTF-8 file name now fails rather
  than reporting a U+FFFD path. `Finding.file_path` is a `String` and cannot
  hold the real bytes; there is no honest third option.
- **Finding identity moves for the affected files.** The fingerprint and dedup
  key are derived from `file_path`, so a finding already stored under an encoded
  path is not recognized as the same durable finding as the one rediscovered
  under the decoded name. That is the defect being corrected, not a migration
  this commit performs.
- **`kuzushi-mcp-codeql::tools.rs::sarif_step` has the same defect and is not
  fixed here.** It reads `artifactLocation.uri` verbatim into the `file` it hands
  the agent. That crate does not depend on `kuzushi-core`, so sharing this helper
  with it is a different change — either a move into `kuzushi-mcp-common` or a
  dependency edge — and belongs in its own commit.
- **`report/application.rs::sarif_file_counts` counts raw `uri` strings** for the
  per-file counts in a report line. Those are display labels over a document
  Kuzushi itself encoded, so the names printed there are the encoded ones. Not
  touched: fixing it means restructuring the counter to own its strings, and it
  changes no finding.
- A reference whose decoded form escapes the repository root is not newly
  reachable: `../x` needs no escape to be written and was never decoded,
  so containment stays the consumer's responsibility exactly as before.
- The `scan/engines/codeql/hex_value/` directory now holds nothing to do with
  hex values — it bundles binary resolution, input values, language detection
  and suite paths. Renaming it is nine file moves with no behavior change and
  would not be independently reviewable beside this fix.
