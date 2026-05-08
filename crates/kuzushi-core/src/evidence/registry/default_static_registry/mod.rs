use super::*;
use std::sync::LazyLock;

mod go_entries;
mod path_entries;
mod python_entries;
mod rust_entries;
mod typescript_entries;

use go_entries::GO_REGISTRY_ENTRIES;
use path_entries::PATH_REGISTRY_ENTRIES;
use python_entries::PYTHON_REGISTRY_ENTRIES;
use rust_entries::RUST_REGISTRY_ENTRIES;
use typescript_entries::TYPESCRIPT_REGISTRY_ENTRIES;

pub(crate) static DEFAULT_STATIC_REGISTRY: LazyLock<Vec<StaticRegistryEntry>> =
    LazyLock::new(|| {
        let mut entries = Vec::new();
        entries.extend_from_slice(TYPESCRIPT_REGISTRY_ENTRIES);
        entries.extend_from_slice(PYTHON_REGISTRY_ENTRIES);
        entries.extend_from_slice(GO_REGISTRY_ENTRIES);
        entries.extend_from_slice(RUST_REGISTRY_ENTRIES);
        entries.extend_from_slice(PATH_REGISTRY_ENTRIES);
        entries
    });
