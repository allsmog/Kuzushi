use crate::findings::{StaticProofState, TriageVerdict};
use crate::source_span::{extract_source_span, SourceSpan};
use crate::whitebox_static::whitebox_static_proof_state_from_str;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
pub(crate) use static_proof_claim_from_whitebox_schema::*;
use std::path::Path;
pub(crate) use validate_citation_snippet::*;
mod proof_claim_model;
mod proof_claim_validation;
mod proof_evidence_from_object;
mod static_proof_claim_from_whitebox_schema;
pub(in crate::static_proof_validator) use proof_evidence_from_object::*;
#[cfg(test)]
mod tests;
mod validate_citation_snippet;

pub use proof_claim_model::StaticProofAssessment;
pub use proof_claim_model::StaticProofAssessmentStatus;
pub use proof_claim_model::StaticProofCitation;
pub use proof_claim_model::StaticProofClaim;
pub use proof_claim_model::StaticProofEvidence;
pub use proof_claim_model::StaticProofValidation;
pub use proof_claim_model::VerifiedStaticProofCitation;
pub use proof_claim_validation::validate_static_proof_claim;
pub use static_proof_claim_from_whitebox_schema::static_proof_claim_from_whitebox_schema;
pub use static_proof_claim_from_whitebox_schema::verify_static_proof_citation;
