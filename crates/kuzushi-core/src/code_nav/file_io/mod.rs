/// Hard cap on bytes returned in a single read. Beyond this we truncate
/// with a marker so the model can reissue with a narrower line range
/// rather than getting flooded.

/// Read a slice of `input.file` relative to `root`. Returns 1-indexed
/// inclusive line ranges so the model can navigate as it reads.
use super::canonicalise::canonicalise_within;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
mod read_source;
#[cfg(test)]
mod tests;

pub use read_source::read_source;
pub use read_source::ReadSourceInput;
pub use read_source::ReadSourceOutput;
pub use read_source::MAX_READ_BYTES;
