//! Offensive live-target operations.
//!
//! Kuzushi's offensive surface (exploit-chain construction, the pwn loop,
//! prompt-injection red-teaming) becomes *active* here: plays that send real
//! traffic at a target and iterate on the response. Every one of those plays
//! is authorized-only. This bounded context owns the safety invariant that
//! makes that defensible — an [`EngagementScope`] the operator declares and an
//! enforcement gate that refuses by default — so no live play can fire at a
//! host that was not explicitly put in scope.

pub mod chain;
pub mod engagement;
pub mod engagement_scope;
pub mod executor;
pub mod http_probe;
pub mod persistence;
pub mod planner;
pub mod play;
pub mod play_context;
pub mod prompt_injection;
pub mod sandbox_curl;
pub mod spec;
pub mod tool;
pub mod transport;

pub use chain::{run_chain, AttackChain, ChainOutcome};
pub use planner::{run_planned_chain, PlannerBudget, PlannerStep};
pub use engagement::{prepare_chain_run, PreparedChainRun};
pub use persistence::persist_chain_finding;
pub use sandbox_curl::SandboxCurlTransport;
pub use spec::{ChainSpec, PlaySpec};
pub use tool::{execute_offense_chain, execute_offense_planned};
pub use engagement_scope::{EngagementScope, ScopeDecision, ScopeEntry, ScopeTarget, ScopeWindow};
pub use executor::run_play;
pub use http_probe::HttpProbePlay;
pub use prompt_injection::PromptInjectionPlay;
pub use play::{Play, PlayOutcome};
pub use play_context::{AuthorizedTarget, PlayContext};
pub use transport::{PlayRequest, PlayResponse, PlayTransport};
