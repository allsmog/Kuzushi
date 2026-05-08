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
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod detail;
mod reporting;

mod items_1;
mod items_2;
mod items_3;
mod items_4;
mod items_5;
mod items_6;
mod items_7;
mod now_isoish;
mod open;
#[cfg(test)]
mod tests;

pub use detail::{
    proof_ladder_state, proof_state_label, runtime_validation_label, FindingDetailReport,
    FindingNextAction, ProofLadderState,
};
pub use items_1::Severity;
pub use items_1::VulnSource;
pub use items_2::compute_dedup_key;
pub use items_2::normalize_cwe;
pub use items_2::Finding;
pub use items_3::extract_cwe;
pub use items_4::PatchStatus;
pub use items_4::StaticProofState;
pub use items_4::TriageOutcome;
pub use items_5::PatchAttempt;
pub use items_5::PatchResult;
pub use items_5::PersistedProofVerdict;
pub use items_5::PersistedVerification;
pub use items_5::TriageVerdict;
pub use items_6::FindingStore;
pub use items_6::PersistedSandboxBackend;
pub(in crate::findings) use items_7::merge_tool_list;
pub(in crate::findings) use items_7::merge_vuln_source;
pub use reporting::{
    format_finding_alias, parse_finding_alias, resolve_finding_alias, sorted_finding_aliases,
    stable_finding_alias, FindingListFilter, FindingListReport, FindingVerdictFilter,
};
