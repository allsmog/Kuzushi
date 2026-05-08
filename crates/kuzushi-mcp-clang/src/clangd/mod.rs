use super::prelude::*;
use super::*;

mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod prelude;
/// Decode an LSP `Location` (or `Location[]`) JSON shape into
/// `(file, line, column)` triples.

#[cfg(test)]
mod tests;
pub use items_1::ClangdClient;
pub use items_3::parse_locations;
