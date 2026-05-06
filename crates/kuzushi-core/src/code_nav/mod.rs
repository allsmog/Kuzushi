//! Read-only code navigation tools used by the deep auditor and other
//! tool-augmented agents.
//!
//! Four tools are exposed today:
//!
//! * `read_source(file, start_line?, end_line?)` — bounded file read with
//!   path canonicalisation against the workspace root.
//! * `find_references(symbol)` — `rg -nw '<symbol>'` over the workspace.
//! * `list_definitions(file)` — regex-based scan for function definitions.
//! * `read_definition(name, hint_file?)` — combine the above to produce a
//!   single best-effort `{file, range, source}` lookup.
//!
//! All tools enforce a path canonicalisation guard: paths must resolve
//! inside `cwd`. `..`-style escapes are rejected with a structured error
//! result rather than a panic — so a malformed model tool call can't read
//! `/etc/passwd` even if the model decides to try.
//!
//! Tree-sitter and `universal-ctags` integration is deliberately not in
//! this initial cut. Both can be layered as backends behind the same tool
//! surface in a later phase: the model schema doesn't change, just the
//! impl quality (better symbol resolution, fewer regex-induced misses).

pub mod canonicalise;
pub mod file_io;
pub mod ripgrep;
pub mod symbol_index;
pub mod tools;

pub use canonicalise::{canonicalise_within, CanonicaliseError};
pub use tools::{
    code_nav_tool_specs, code_nav_toolbox, find_references_tool, list_definitions_tool,
    read_definition_tool, read_source_tool, CodeNavConfig, CodeNavTool,
};
