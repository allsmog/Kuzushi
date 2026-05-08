mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod proof_evidence_from_object;
pub use proof_evidence_from_object::*;
#[cfg(test)]
mod tests;
mod validate_citation_snippet;

pub use items_1::StaticProofAssessment;
pub use items_1::StaticProofAssessmentStatus;
pub use items_1::StaticProofCitation;
pub use items_1::StaticProofClaim;
pub use items_1::StaticProofEvidence;
pub use items_1::StaticProofValidation;
pub use items_1::VerifiedStaticProofCitation;
pub use items_2::validate_static_proof_claim;
pub use items_3::static_proof_claim_from_whitebox_schema;
pub use items_3::verify_static_proof_citation;
