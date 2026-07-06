mod contract;

pub use contract::DeepAuditConfig;
pub use contract::DeepAuditOutcome;
pub use contract::EvidenceCitation;
pub use contract::VulnAnalysis;
pub use contract::DEFAULT_DEPOSIT_USD;
pub use contract::DEFAULT_MAX_STEPS;
pub use contract::DEFAULT_PASSES;
pub(crate) use contract::deep_auditor_system_prompt;
pub use contract::DEFAULT_TEMPERATURE;
