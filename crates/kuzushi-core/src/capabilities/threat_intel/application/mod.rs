mod apply;
pub(crate) mod dispatch;
mod harvest;
pub(crate) mod regression_gate;

pub use apply::{apply_threat_intel_catalog, list_threat_intel_catalog, resolve_catalog_path};
pub use harvest::harvest_threat_intel_catalog;
pub use regression_gate::{
    apply_regression_gate_to_entries, run_regression_gate, RegressionGateOutcome,
    RegressionGateStatus,
};
