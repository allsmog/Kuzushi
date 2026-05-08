use super::prelude::*;
use super::*;

mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
/// Parse a single line of `global -x` output. Returns `None` for empty or
/// malformed lines (gtags occasionally emits warnings on stdout that we
/// must skip).
///
/// Layout: `symbol  line  file  snippet` separated by runs of whitespace.
/// The snippet may contain embedded whitespace (and tabs), so we identify
/// the first three fields with `split_whitespace` and slice the original
/// line for the rest.

/// Walk `line` matching each `field` in order, returning the byte offset
/// just past the last match. `None` if any field can't be located in
/// sequence — that means `line` doesn't actually contain those tokens
/// where they were expected.

/// Parse the entirety of a `global -x` document.

/// Convert a parsed record list to fully-resolved [`Symbol`]s, prefixing
/// each file path with `repo_root` when the path is relative (gtags
/// emits relative paths by default).

#[cfg(test)]
mod tests;
pub use items_1::parse_global_x;
pub use items_1::parse_global_x_line;
pub use items_1::records_to_symbols;
pub use items_1::GtagsRecord;
