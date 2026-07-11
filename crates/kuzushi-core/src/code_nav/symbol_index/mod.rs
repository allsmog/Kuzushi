use super::canonicalise::canonicalise_within;
use super::file_io::{read_source, ReadSourceInput};
use super::ripgrep::{find_references, FindReferencesInput};
use anyhow::{Context, Result};
pub(in crate::code_nav) use scan_c_like::*;
pub(in crate::code_nav) use scan_go::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
mod list_definitions;
mod read_definition;
mod scan_c_like;
mod scan_go;
pub(in crate::code_nav::symbol_index) use read_definition::classification::{
    is_ident, keyword_at_start,
};
pub use read_definition::*;
#[cfg(test)]
mod tests;

pub use list_definitions::list_definitions;
pub use list_definitions::DefinitionEntry;
pub use list_definitions::ListDefinitionsInput;
pub use list_definitions::ListDefinitionsOutput;
