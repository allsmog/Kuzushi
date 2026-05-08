/// Discovery channel a finding came from. Mirrors RoboDuck's `VulnSource`.

/// 16-line bucket size — picked so a function-sized vulnerability
/// reported across two channels at lines 42 and 47 collides, but
/// findings 30 lines apart in the same file don't.

/// Compute a cross-channel dedup key.
///
/// `(normalised_file, line / 16, normalised_cwe)`.
///
/// CWE comparison is normalised via `normalize_cwe` so `CWE-787`,
/// `cwe-787`, `CWE_787`, and `787` collapse to the same string.

/// Lower-cased CWE id with the leading `cwe-` prefix removed; non-digit
/// junk is stripped. So `CWE-787`, `cwe-787`, `CWE_787`, ` 787 ` all
/// normalise to `787`.

/// Best-effort CWE extraction from a finding's message + rule_id +
/// title. Looks for `CWE-\d+`. Returns the first hit only.

/// Persisted form of a `VerificationOutcome`. Lives here (rather than in
/// `crate::verify`) to avoid a circular dep — the verify module
/// constructs these from its richer in-memory types when persisting.

/// Merge a comma-separated tool list `existing` with a new `incoming`
/// tool name. Order is stable (sorted) so the test output is
/// deterministic.

/// Merge two `VulnSource` values: keep the existing if both are set,
/// since tool merging already records the new channel via the tool list.
use anyhow::{Context, Result};
pub(in crate::findings) use now_isoish::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
pub(in crate::findings) use store_rows::*;
mod detail;
mod reporting;

mod extract_cwe;
mod finding_record;
mod finding_store;
mod from_semgrep;
mod now_isoish;
mod open;
mod patch_status;
mod persisted_results;
mod static_proof_state;
mod store_rows;
#[cfg(test)]
mod tests;
mod triage_outcome;

pub use detail::{
    proof_ladder_state, proof_state_label, runtime_validation_label, FindingDetailReport,
    FindingNextAction, ProofLadderState,
};
pub use extract_cwe::extract_cwe;
pub use finding_record::compute_dedup_key;
pub use finding_record::normalize_cwe;
pub use finding_record::Finding;
pub use finding_store::FindingStore;
pub use finding_store::PersistedSandboxBackend;
pub use from_semgrep::Severity;
pub use from_semgrep::VulnSource;
pub use patch_status::PatchStatus;
pub use persisted_results::PatchAttempt;
pub use persisted_results::PatchResult;
pub use persisted_results::PersistedProofVerdict;
pub use persisted_results::PersistedVerification;
pub use persisted_results::TriageVerdict;
pub use reporting::{
    format_finding_alias, parse_finding_alias, resolve_finding_alias, sorted_finding_aliases,
    stable_finding_alias, FindingListFilter, FindingListReport, FindingVerdictFilter,
};
pub use static_proof_state::StaticProofState;
pub(in crate::findings) use store_rows::merge_tool_list;
pub(in crate::findings) use store_rows::merge_vuln_source;
pub use triage_outcome::TriageOutcome;
