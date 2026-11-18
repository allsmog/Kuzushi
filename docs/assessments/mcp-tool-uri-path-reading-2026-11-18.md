# Reading the path an MCP server's upstream URI names — 2026-11-18

## The defect

Two of Kuzushi's Rust MCP servers answered an agent's location question with a
URI where the agent expects a filesystem path.

RFC 3986 lets no byte outside the unreserved set stand in a URI reference, so
every producer these servers read escapes an ordinary file name:

- clangd answers `textDocument/definition` and `textDocument/references` with
  `file:///tmp/a%20b.c` for `/tmp/a b.c`.
- `codeql database analyze` writes `src/caf%C3%A9.rs` in
  `artifactLocation.uri` for `src/café.rs`. SARIF 2.1.0 §3.4.3 requires it.

`kuzushi-mcp-clang`'s `clangd::locations::one_location` stripped `file://` and
returned the rest verbatim, and the same crate's
`clangd::protocol::file_uri` encodes the URIs it *sends* with
`url::Url::from_file_path` — its own test asserts
`file:///tmp/a%20b%23%25%C3%A9.c`. So the crate encoded one direction and
declined to decode the other.

`kuzushi-mcp-codeql`'s `tools::sarif_step` read `artifactLocation.uri` straight
into the `file` of each `{file,line,code}` step that `codeql:flows_for_cwe` and
`codeql:query` return. That was recorded as an unfixed follow-up in
`docs/assessments/sarif-relative-uri-reading-2026-11-17.md`, which fixed the
same reading inside `kuzushi-core` and left these servers alone because they do
not depend on that crate.

Both answers are what the agent opens next: it reads the named file to judge the
candidate, and the tools it chains to (`tree_sitter:node_at`, `cpg.method_at`)
take a path. `/tmp/a%20b.c` names no file. Nothing can open it, the chained call
fails on a name the agent has no reason to distrust, and a flow the engine
genuinely found is dropped or mis-attributed with no disclosure that the name
was never the engine's.

## Why it ranked first

It is a correctness defect in the primary output of two agent-facing tools, on
the verification path (`taint-iris-next:hunt` turns `toolPolicy.mcps` on
precisely so the agent can confirm or refute a candidate against CodeQL and the
AST). It needs no unusual configuration: one space or one non-ASCII byte in a
source file name is enough. The fix is the inverse of an encoder one of the two
crates already uses, and the duplication that produced the defect — three
hand-written copies of the same reading, one per consumer — is what the
2026-11-17 commit had just finished removing inside `kuzushi-core`.

## What changed

`kuzushi_mcp_common::tool_uri::reported_path` owns the reading once. Both
servers already depend on `kuzushi-mcp-common`, and so does `kuzushi-core`, so
no new dependency edge was added; `url` and `percent-encoding` were already in
the workspace lock through `kuzushi-mcp-clang` and `kuzushi-core`.

The policy:

- A `file:` URI reads back through `Url::to_file_path`, the exact inverse of the
  `Url::from_file_path` encoder `kuzushi-mcp-clang` already uses. A URI naming a
  non-local host (`file://build01/share.c`) has no local path and is `None`
  rather than the fabricated relative `build01/share/a.c` the old strip
  produced. `Url` normalizes an empty path to the root, so a URI with no file
  name is `None` instead of `/`.
- Any other scheme is returned verbatim: it names an identifier, not a path, and
  `%2F` inside a query string is not a separator.
- A relative reference — what CodeQL writes for every result inside the analyzed
  tree — is percent-decoded and stays relative, because the root it resolves
  against is the caller's to name.
- A single-letter scheme is read as a Windows drive letter, so `C:/work%20dir`
  still gets the decoding its escapes need.
- A reference that decodes to bytes that are not UTF-8 is `None`. A path holding
  U+FFFD names a different file than the one the tool found, and these answers
  travel as JSON strings.

## Verification

The four new consumer regression tests fail against the prior readings with the
fabricated names printed verbatim — `/tmp/a%20b%23%25%C3%A9.c` and
`src/caf%C3%A9/My%20Query.c` — and pass after. Ten policy tests cover the
branches in `tool_uri`.

## What this does not claim

- **Locations are now skipped, not renamed.** A non-local `file://` host, a URI
  with no file name, and a non-UTF-8 escape sequence each drop one location
  where the old code reported a fabricated one. Both call sites already collect
  with `filter_map`, so a dropped step is the shape they were written for, but
  it is a behavior change and not merely a decoding.
- **`kuzushi-core`'s `reported_path_from_sarif_uri` is not merged into this
  helper.** It carries SARIF-specific policy the MCP servers must not have —
  it strips an absolute path's root prefix because a finding's path is reported
  relative to the workspace, where an MCP answer has to stay openable as given.
  Unifying them means moving that stripping to core's call sites, which is a
  change to the just-corrected scan path and belongs in its own commit.
- **No separator rewriting.** A literal `\` is left alone: it is an ordinary
  filename byte on Unix, neither producer emits one in a URI, and the escape is
  reversible where a wrong split is not. `kuzushi-core` normalizes it for SARIF
  documents written by other emitters; that reading stays there.
- **`report/application.rs::sarif_file_counts`** still counts raw `uri` strings
  for a report line. Unchanged from the 2026-11-17 assessment: they are display
  labels over a document Kuzushi itself encoded, and fixing them changes no
  finding.
