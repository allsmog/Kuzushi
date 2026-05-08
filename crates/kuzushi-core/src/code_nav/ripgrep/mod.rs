/// Hard cap on result count — prevents the model from being flooded by a
/// generic name (e.g. `i`, `tmp`, or a popular type).

/// Where the `rg` binary lives. Override via `KUZUSHI_RIPGREP_BIN` for
/// tests or non-standard installations.
use super::canonicalise::canonicalise_within;
use anyhow::{Context, Result};
pub(in crate::code_nav) use ripgrep_binary::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};
mod find_references;
mod ripgrep_binary;
#[cfg(test)]
mod tests;

pub use find_references::find_references;
pub use ripgrep_binary::FindReferencesInput;
pub use ripgrep_binary::FindReferencesOutput;
pub use ripgrep_binary::ReferenceHit;
pub use ripgrep_binary::MAX_REFERENCES;
