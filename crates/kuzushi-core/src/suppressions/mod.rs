//! Unified suppression primitive.
//!
//! One composable `SuppressionRule` (predicate + reason + statement + actor +
//! optional expiry) that all muting concepts compile into: false-positive
//! dismissal, program-scope gating, severity muting, legacy whitebox snippet
//! suppressions, and in-source `# kuzushi-ignore:` comments.
//!
//! Evaluation is uniform (findings are annotated, never deleted — Grype's
//! model) and expiry-aware (read-time truth plus a durable reconcile sweep that
//! auto-reopens lapsed suppressions via the event log — Trivy's model).

pub mod application;
pub mod domain;
pub mod persistence;

pub use application::{
    compile_scope_rule, compile_whitebox_rules, effective_suppression_rules,
    reconcile_suppression_events, run_suppression_sweep, scan_ignore_comments, EffectiveRules,
    IgnoreCommentScan, SuppressionReconcileSummary, SuppressionSweep,
};
pub use domain::{
    evaluate_suppressions, evaluate_with_comment_diagnostics, finding_stable_fp,
    parse_utc_date_to_unix, FindingRef, SuppressionMatch, SuppressionOrigin, SuppressionPredicate,
    SuppressionReason, SuppressionReport, SuppressionRule, SuppressionState, SuppressionStateEntry,
};
pub use persistence::{
    derive_rule_id, load_suppression_rules, remove_suppression_rule, save_suppression_rules,
    upsert_suppression_rule,
};
