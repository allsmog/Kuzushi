//! Review yield: census of human adjudication and leakage-safe export of
//! event-bounded training examples.
//!
//! The bounded context owns three things and nothing else:
//!
//! 1. the label policy (which human verdicts are positive, negative, or
//!    excluded),
//! 2. the feature whitelist and its normalizers, and
//! 3. as-of extraction — features are read only from finding snapshots that
//!    existed at or before the decider's read cutoff.
//!
//! It never imports `findings::presentation` (proof ladder / confidence
//! presentation) or the static-evidence store, and it never reads the
//! label-adjacent projection fields (`$.triage`, `$.triaged_by`,
//! `$.suppressed`, `$.snoozed_until`, `$.verification`). The whitelist
//! deserialization in `application::extract_features` is the enforcement
//! mechanism, not a convention.

pub mod application;
pub mod domain;
pub mod persistence;

#[cfg(test)]
mod tests;
