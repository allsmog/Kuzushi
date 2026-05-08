use super::*;

mod siblings;
pub(crate) use siblings::*;
mod items_1;
/// Escape a string for embedding in a Scala double-quoted literal. Mirrors
/// the cases joern actually trips on: backslash, double quote, newline.

/// `cpg.method.name(<fn>).caller.l` — methods that call `fn`.

/// `cpg.method.name(<fn>).callee.l` — methods called by `fn`.

/// Taint path query: methods reaching `sink` from `source` via joern's
/// `reachableByFlows`. Returns a list of paths; each path is a sequence
/// of CPG nodes from a source identifier to the sink call.

/// Reaching-definition query for a variable at a specific (file, line).
/// Returns the definitions that flow into the identifier at that
/// location.

/// Locate `unsafe { ... }` regions via joern's Rust frontend. Joern's
/// Rust support tags unsafe blocks with a code prefix; we match by
/// regex against the call/block code. Constrained by file when
/// supplied, otherwise repo-wide.

/// FFI-boundary query: locate `extern \"C\"` declarations (Rust + C),
/// `extern fn` (Rust), and JNI / dlsym calls. One Scala query, two
/// joern node types unioned.

/// Locate the method enclosing a (file, line) coordinate.

/// `cpg.method.fullName(...).numberOfLines` — small ergonomic check.

#[cfg(test)]
mod tests;
pub use items_1::callees_of;
pub use items_1::callers_of;
pub use items_1::cpg_size_query;
pub use items_1::escape_scala_string;
pub use items_1::ffi_boundaries;
pub use items_1::method_at;
pub use items_1::reaching_def;
pub use items_1::taint_paths;
pub use items_1::unsafe_blocks;
