pub(crate) mod adapters;
pub(crate) mod application;
pub mod domain;

#[cfg(test)]
mod tests;

pub use adapters::{
    execute_threat_intel_tool, load_catalog_from_path, parse_catalog_str, SUPPORTED_SCHEMA_VERSIONS,
};
pub(crate) use application::catalog_dispatch_requested;
pub use application::{
    apply_regression_gate_to_entries, apply_threat_intel_catalog, harvest_threat_intel_catalog,
    harvested_threat_intel_catalog_path, list_threat_intel_catalog, resolve_catalog_path,
    run_regression_gate, threat_intel_catalogs_dir, RegressionGateOutcome, RegressionGateStatus,
    HARVESTED_THREAT_INTEL_CATALOG_FILE, THREAT_INTEL_CATALOGS_DIR,
};
pub(crate) use application::{query_osv_candidates, OsvCandidate, OsvPackageQuery, OsvQueryReport};
pub use domain::{CatalogEntry, CatalogFile, CatalogSeverity, HuntKind, RawCatalogEntry};
