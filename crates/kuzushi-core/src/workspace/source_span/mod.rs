use crate::static_evidence::static_content_hash;
use anyhow::{bail, Context, Result};
pub(crate) use resolve_requested_path::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
mod extract_source_span;
mod resolve_requested_path;
#[cfg(test)]
mod tests;

pub use extract_source_span::extract_source_span;
pub use extract_source_span::SourceSpan;
