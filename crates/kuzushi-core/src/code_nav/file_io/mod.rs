/// Hard cap on bytes returned in a single read. Beyond this we truncate
/// with a marker so the model can reissue with a narrower line range
/// rather than getting flooded.

/// Read a slice of `input.file` relative to `root`. Returns 1-indexed
/// inclusive line ranges so the model can navigate as it reads.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
#[cfg(test)]
mod tests;

pub use items_1::read_source;
pub use items_1::ReadSourceInput;
pub use items_1::ReadSourceOutput;
pub use items_1::MAX_READ_BYTES;
