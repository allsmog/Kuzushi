use anyhow::Result;
use serde::{Deserialize, Serialize};
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

/// Stable finding identity: FNV-1a over (rule_id, file_path, start_line),
/// 128 bits rendered as 32 hex chars. Two deliberate properties:
///
/// - **The message is excluded.** Two runs describing the same bug with
///   different wording (LLM phrasing drift, enriched evidence text) must
///   resolve to the same finding, not accumulate duplicates.
/// - **FNV-1a, not `DefaultHasher`.** `DefaultHasher`'s algorithm is
///   explicitly not guaranteed stable across Rust releases or platforms; a
///   toolchain bump must never resurrect every historical finding as "new".
///   FNV-1a matches the static-evidence store's hashing precedent.
///
/// The 32-char length also distinguishes v2 fingerprints from legacy 16-char
/// `DefaultHasher` ones, which `migrate_legacy_fingerprints` rewrites once.
pub(crate) fn fingerprint_parts(rule_id: &str, file_path: &str, start_line: u32) -> String {
    // \u{1f} (unit separator) prevents boundary ambiguity between parts.
    let input = format!("{rule_id}\u{1f}{file_path}\u{1f}{start_line}");
    format!(
        "{:016x}{:016x}",
        fnv1a64(input.as_bytes(), 0xcbf29ce484222325),
        fnv1a64(input.as_bytes(), 0x84222325cbf29ce4),
    )
}

fn fnv1a64(bytes: &[u8], offset_basis: u64) -> u64 {
    let mut hash = offset_basis;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}
