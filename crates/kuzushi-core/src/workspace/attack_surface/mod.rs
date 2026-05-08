use crate::repository_inventory::{
    build_repository_inventory, InventoryRouteController, InventorySourceFile, RepositoryInventory,
};
use crate::static_evidence::static_content_hash;
pub(crate) use add::*;
use anyhow::{Context, Result};
pub(crate) use inspect_go_line::*;
pub(crate) use inspect_node_line::*;
pub(crate) use inspect_python_line::*;
pub(crate) use inspect_rust_line::*;
pub(crate) use inspect_source_file::*;
pub(crate) use node_route_from_line::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
pub(crate) use summarize_surfaces::*;
mod add;
mod attack_surface_model;
mod inspect_go_line;
mod inspect_node_line;
mod inspect_python_line;
mod inspect_rust_line;
mod inspect_source_file;
mod node_route_from_line;
mod summarize_surfaces;
#[cfg(test)]
mod tests;

pub use add::build_attack_surface_map;
pub use add::build_attack_surface_map_from_inventory;
pub use attack_surface_model::AttackSurface;
pub use attack_surface_model::AttackSurfaceKind;
pub use attack_surface_model::AttackSurfaceMap;
pub use attack_surface_model::AttackSurfaceSummary;
