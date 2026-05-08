use super::prelude::*;
use super::*;

// `Stdio` is still used by `parse_repo` below — `joern-parse` is a
// real subprocess (the JVM tool we're wrapping). Only the HTTP query
// path moved to native Rust.

mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
/// Run `joern-parse <repo>` and persist the resulting `cpg.bin.zip` under
/// `~/.kuzushi/index/joern/<repo-hash>/<commit>/`.

/// Run a Scala query against a running `joern --server` instance via a
/// native Rust HTTP client (`reqwest` over `rustls`). Returns the raw
/// stdout payload from joern (a JSON string of the CPG result).

#[cfg(test)]
mod tests;
pub use items_1::parse_repo;
pub use items_1::run_query;
pub use items_1::CpgHandle;
