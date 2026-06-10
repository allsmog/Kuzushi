//! Offensive live-target operations.
//!
//! Kuzushi's offensive surface (exploit-chain construction, the pwn loop,
//! prompt-injection red-teaming) becomes *active* here: plays that send real
//! traffic at a target and iterate on the response. Every one of those plays
//! is authorized-only. This bounded context owns the safety invariant that
//! makes that defensible — an [`EngagementScope`] the operator declares and an
//! enforcement gate that refuses by default — so no live play can fire at a
//! host that was not explicitly put in scope.

pub mod engagement_scope;

pub use engagement_scope::{
    EngagementScope, ScopeDecision, ScopeEntry, ScopeTarget, ScopeWindow,
};
