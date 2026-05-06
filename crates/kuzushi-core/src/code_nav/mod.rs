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
//! Tree-sitter is the primary symbol-index backend (Track C); it falls
//! back to per-language regex scanners (`scan_*` in `symbol_index.rs`)
//! when tree-sitter doesn't recognise the language, the parse fails,
//! or a brittle grammar panics. The fallback keeps the backend safe on
//! macro-heavy / template-heavy / partially-broken source.

pub mod canonicalise;
pub mod file_io;
pub mod ripgrep;
pub mod symbol_index;
pub mod tools;
pub mod treesitter;

pub use canonicalise::{canonicalise_within, CanonicaliseError};
pub use tools::{
    code_nav_tool_specs, code_nav_toolbox, find_references_tool, list_definitions_tool,
    read_definition_tool, read_source_tool, CodeNavConfig, CodeNavTool,
};
