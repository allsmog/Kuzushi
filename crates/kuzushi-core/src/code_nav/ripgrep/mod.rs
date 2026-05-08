/// Hard cap on result count — prevents the model from being flooded by a
/// generic name (e.g. `i`, `tmp`, or a popular type).

/// Where the `rg` binary lives. Override via `KUZUSHI_RIPGREP_BIN` for
/// tests or non-standard installations.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod find_references;
mod items_1;
#[cfg(test)]
mod tests;

pub use find_references::find_references;
pub use items_1::FindReferencesInput;
pub use items_1::FindReferencesOutput;
pub use items_1::ReferenceHit;
pub use items_1::MAX_REFERENCES;
