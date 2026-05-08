use crate::evidence::static_evidence::{StaticEvidenceNode, StaticEvidenceStore};
use crate::findings::{Finding, StaticProofState};
use anyhow::Result;
pub(crate) use candidate_report::*;
pub(crate) use matching_tokens::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(crate) use synthesize_candidate_for_finding::*;
pub(crate) use validate_candidate::*;
mod candidate_report;
mod matching_tokens;
mod positive;
mod synthesize_candidate_for_finding;
#[cfg(test)]
mod tests;
mod validate_candidate;

pub use candidate_report::SemgrepCandidateRule;
pub use candidate_report::SemgrepRuleSynthesisReport;
pub use candidate_report::SemgrepRuleValidation;
pub use positive::synthesize_candidate_semgrep_rules;
pub use positive::SemgrepRuleFixture;
