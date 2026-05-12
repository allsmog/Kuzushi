pub(crate) mod adapters;
pub(crate) mod application;
pub mod domain;

#[cfg(test)]
mod tests;

pub use adapters::{
    execute_threat_intel_tool, load_catalog_from_path, parse_catalog_str, SUPPORTED_SCHEMA_VERSIONS,
};
pub use application::{
    apply_regression_gate_to_entries, apply_threat_intel_catalog, harvest_threat_intel_catalog,
    list_threat_intel_catalog, resolve_catalog_path, run_regression_gate, RegressionGateOutcome,
    RegressionGateStatus,
};
pub use domain::{CatalogEntry, CatalogFile, CatalogSeverity, HuntKind, RawCatalogEntry};
