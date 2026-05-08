/// Hard cap on tool-loop steps per finding. Mirrors RoboDuck's tool-loop
/// budget — large enough that the model can read several files but small
/// enough that a runaway loop is bounded.

/// Conservative initial deposit per audit. Real cost surfaces from the
/// bridge per-step and settles via SpendLimiter::refund.

/// What the model is asked to return as its final structured answer.

/// Run a tool-augmented deep audit on a single finding.
///
/// `runtime` should be a `RoutedRuntime` so the model is selected by the
/// `DeepAuditor` role. Per-call enforcement uses the supplied
/// [`SpendLimiter`]; pass `None` to skip budgeting (tests / dry-runs).

/// Salvage evidence from tool transcripts when the model didn't return
/// any in its structured answer. We pick out file/line ranges from
/// successful read_source calls and the matching arguments.

/// Persist evidence citations into the optional `findings_evidence`
/// table. Best-effort — failures log but don't propagate, since the
/// audit verdict itself is the primary artefact.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
#[cfg(test)]
mod tests;

pub use items_1::DeepAuditConfig;
pub use items_1::DeepAuditOutcome;
pub use items_1::EvidenceCitation;
pub use items_1::VulnAnalysis;
pub use items_1::DEFAULT_DEPOSIT_USD;
pub use items_1::DEFAULT_MAX_STEPS;
pub use items_2::run_deep_auditor;
pub use items_4::save_evidence;
