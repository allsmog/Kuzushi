use crate::findings::{Finding, StaticProofState};
use crate::static_ranking::StaticRankedFinding;
use anyhow::Result;
use serde::Serialize;
pub(crate) use static_finding_narrative::*;
use std::collections::HashMap;
mod build_static_narrative_report;
mod static_finding_narrative;
#[cfg(test)]
mod tests;

pub use build_static_narrative_report::build_static_narrative_report;
pub use build_static_narrative_report::validate_static_narrative_text;
pub use build_static_narrative_report::StaticFindingNarrative;
pub use build_static_narrative_report::StaticNarrativeReport;
