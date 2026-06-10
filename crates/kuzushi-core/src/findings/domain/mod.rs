use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

mod extract_cwe;
mod finding_record;
mod from_semgrep;
mod now_isoish;
mod patch_status;
mod persisted_results;
mod static_proof_state;
mod triage_outcome;

pub use extract_cwe::extract_cwe;
pub use finding_record::{
    compute_dedup_key, compute_root_cause_key, normalize_cwe, Finding, FindingEvidence,
};
pub use from_semgrep::{Severity, VulnSource};
pub(crate) use now_isoish::now_isoish;
pub use patch_status::PatchStatus;
pub use persisted_results::{
    PatchAttempt, PatchResult, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, TriageVerdict,
};
pub(crate) use static_proof_state::is_runtime_proof_state;
pub use static_proof_state::StaticProofState;
pub use triage_outcome::TriageOutcome;

pub(crate) fn fingerprint_parts(
    rule_id: &str,
    file_path: &str,
    start_line: u32,
    message: &str,
) -> String {
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    file_path.hash(&mut hasher);
    start_line.hash(&mut hasher);
    message.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
