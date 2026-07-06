mod application;
mod domain;
mod persistence;

#[cfg(test)]
mod tests;

pub use application::run_deep_auditor;
pub use domain::DeepAuditConfig;
pub use domain::DeepAuditOutcome;
pub use domain::EvidenceCitation;
pub use domain::VulnAnalysis;
pub use domain::DEFAULT_DEPOSIT_USD;
pub use domain::DEFAULT_MAX_STEPS;
pub use domain::DEFAULT_PASSES;
pub use domain::DEFAULT_TEMPERATURE;
pub use persistence::record_evidence;
