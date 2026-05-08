mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod path;
/// A short snippet of source attached to a symbol or location — useful for
/// caller/callee result presentation without forcing the consumer to re-read
/// the file.

/// Kind of edge connecting two positions in a `Path`.

/// A taint / dataflow path returned by joern.

#[cfg(test)]
mod tests;

pub use items_1::EdgeKind;
pub use items_1::FileSpan;
pub use items_1::Method;
pub use items_1::MethodParameter;
pub use items_1::Position;
pub use items_1::Range;
pub use items_1::Symbol;
pub use items_1::SymbolKind;
pub use path::Path;
