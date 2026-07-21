//! Kuzushi reporting boundary.
//!
//! Report producers consume persisted findings and run artifacts. They should
//! not run scanners, dispatch tools, or ask an LLM for new evidence.

mod application;
mod artifact_summary;
mod confirmed_sarif;
mod domain;
mod failure_handoff;
mod markdown;
#[cfg(test)]
mod tests;

pub use application::build_run_report;
pub use confirmed_sarif::execute_report_sarif;
pub use domain::{CanonicalReportArtifact, ReportFailureHandoff, RunReportBuild};
pub use crate::findings::FindingListReport;
pub use crate::pr_comment::build_pr_comment;
pub use crate::run_artifacts::{load_run_artifacts, load_run_summary, RunArtifactManifest};
