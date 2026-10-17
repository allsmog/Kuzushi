# Selected compiler input and honest prerequisites

UAF navigation now binds the selected compiler database to a bounded private
copy. The client checks the helper API and health before model work. Compiler
identity remains readable after completion and restart. The action stays
auxiliary Labs Scan work and cannot complete Scan. Publication stays a draft on
`main`.

## Failure and repair

The before-fix regression supplied a custom database, then inspected the actual
navigation request. No selected database reached it. The original argument was
accepted and reported while helper startup discarded it.

Shared dispatch retains `compileCommandsPath` as a workspace read. The additive
`externalCompileCommandsPath` option, with alias `external_compile_commands_path`,
accepts a separately selected operator file. External reads cannot come from
workspace-stored options. Supplying both paths fails explicitly. Existing root
and `build/compile_commands.json` defaults remain.

One shared snapshot implementation authenticates a no-follow file read, limits
source and prepared JSON to 8 MiB each, validates command structure and caps the
list at 100000 commands. Relative working directories bind to the original
database directory. Arbitrary filenames are retained as a private
`compile_commands.json`. The navigation helper receives the target read root
and the private copy, without a grant to the external file's parent directory.
Model-supplied arguments cannot replace the bound target or compiler file.

The helper accepts an optional `compileCommandsPath` on navigation and metadata
tools. Its clangd client cache compares repository and compiler identity.
Explicit selection uses a private compiler directory, disables repository
configuration and disables compiler-driver probing. The existing read-only
process sandbox remains required. The implementation follows the documented
[clangd compilation database interface](https://clangd.llvm.org/faq) and
[driver probing contract](https://clangd.llvm.org/design/compile-commands).

Initialization, tool-schema compatibility and health checks finish before model
requests. Missing or incompatible helpers, dependencies or sandbox support fail
without a fallback. Metadata requests use the same bounded transport, deadline
and cancellation. Local compiler capture starts no model request or build.

## Receipt and compatibility

`data.compileDatabase` records original path, source and prepared SHA-256,
source and prepared bytes, and command count. The primary result names the count
and frozen input. Replay Inputs presents an identity receipt and explicitly
omits command contents and the model prompt. It does not claim complete model
context retention.

Existing tool names, pair options, workspace path semantics, transcript paths,
partial outcomes and unknown-cost handling remain. Old serialized UAF reports
default the optional compiler receipt to absent. Rust struct literals add
`compile_database: None` for legacy data. A matching helper is required for the
new configuration protocol. Direct MCP calls without explicit selection keep
their existing default lookup.

## Verification

The before-fix regression, bounded-file checks, shared preparation checks and
real read-only clangd checks are retained in the evidence directory. Real
clangd uses the selected command over conflicting root and repository config,
and changing the same selected file replaces its cached client. No target
program is executed.

All 101 distinct focused checks, the workspace build and all ten repository
gates pass. The risk proxy covers 500 changed code files. Final sequential
J329/J328/J279 have 116 machine passes, zero failures, 111 authenticated capture
pairs and eleven pending human UX judgments. Eighteen terminal-cell replays
were inspected; these are ANSI replays, not OS screenshots.

J329 checks shell then headless under one allowance of five calls,
including one protected Review call. Four requests are intercepted. The original
database changes after capture while actual definition navigation continues to
use the private copy. Both the initial unapproved request and the exhausted
request retain distinct blocked receipts. Restart preserves the original
compiler identity and protected Review capacity. No live request is made.

Two fixture assertion failures are retained: End placed an expected notice
above the final narrow viewport, and the receipt check initially counted only
one of two legitimate refusals. The final journey pages through the notice and
checks both refusal reasons. Production binaries are unchanged between native
attempts. The final matrix uses six intercepted requests; the two retained
attempts used six more. All twelve are synthetic transport calls.

A full disk interrupted an earlier compile. Duplicate frozen binaries were
replaced with identical hard links, retaining every path and its bytes; failed
compile objects were removed. The final build and gates completed afterward.

## Qualification still open

Only the identity receipt persists after a completed invocation. Full compiler
commands, frozen source/context, crash recovery and detector usefulness still
need qualification. Ordinary client teardown removes its private compiler copy;
this does not establish cleanup after an abrupt process kill.

Source/finding/graph grounding, read/list truncation, scoped discovery and real
model usefulness remain open for UAF. Source-only compiler navigation qualifies
the repaired input path. It does not qualify security findings or complete the
investigation plan. All nine broad milestones remain open.

Evidence: `/tmp/kuzushi-clang-database-selection-20261017`. Historical live model
usage remains fourteen with no remaining allowance. No project commit or push
is added. Exploit development, reproducer work and vulnerability patching remain
excluded.
