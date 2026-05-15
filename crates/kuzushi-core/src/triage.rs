//! Kuzushi triage boundary.
//!
//! Triage attaches model-backed verdicts to existing findings; scanners should
//! never perform this classification directly.

pub use crate::findings::{TriageOutcome, TriageVerdict};
