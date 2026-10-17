use anyhow::{Context, Result};
pub(crate) use extract_first_quoted::*;
pub(crate) use generated_vendor_path::*;
pub(crate) use inspect_entrypoints::*;
pub(crate) use inspect_manifest_frameworks::*;
pub(crate) use inspect_python_route_line::*;
pub(crate) use inspect_source_frameworks::*;
pub(crate) use language_for_path::*;
pub(crate) use manifest_package_tokens::*;
pub(crate) use repository_inventory::*;
pub(crate) use route_item::*;
use serde::{Deserialize, Serialize};
pub(crate) use source_text_scan::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
mod add_source_file;
mod build_repository_inventory;
pub(crate) use build_repository_inventory::{
    build_repository_inventory_from_enumeration, MAX_REPOSITORY_ENTRIES,
    MAX_REPOSITORY_INSPECTED_BYTES,
};
mod extract_first_quoted;
mod generated_vendor_path;
mod inspect_entrypoints;
mod inspect_manifest_frameworks;
mod inspect_python_route_line;
mod inspect_source_frameworks;
mod language_for_path;
mod manifest_package_tokens;
mod python_route_frameworks;
mod repository_inventory;
mod route_item;
mod source_prefixes;
mod source_text_scan;
pub(crate) use source_prefixes::{
    collect_source_prefixes, SourcePrefix, SourcePrefixLimits, SourcePrefixes,
};
mod target_kind;
#[cfg(test)]
mod tests;

pub use build_repository_inventory::{
    build_repository_inventory, build_repository_inventory_with_observer,
    build_repository_inventory_with_progress,
};
pub use repository_inventory::InventoryEntrypoint;
pub use repository_inventory::InventoryFile;
pub use repository_inventory::InventoryFramework;
pub use repository_inventory::InventoryInspection;
pub use repository_inventory::InventoryLanguage;
pub use repository_inventory::InventoryPathClassification;
pub use repository_inventory::InventoryRouteController;
pub use repository_inventory::InventorySourceFile;
pub use repository_inventory::InventoryTruncation;
pub use repository_inventory::RepositoryInventory;
pub use target_kind::{
    classify_target_kind, target_has_compile_commands, TargetKind, TargetProfile,
};
