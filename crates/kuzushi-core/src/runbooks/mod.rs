//! Code-first phase runbooks for app-orchestrated LLM workflows.
//!
//! The TUI keeps dispatching ordinary tools (`agentic-sast:scan`, `triage:run`,
//! `patch:finding`, ...). Tool implementations can opt into these runbook
//! helpers to get stable phase/step labels, checkpoint artifacts, fanout
//! bookkeeping, and shared prompt hardening without introducing a second
//! user-facing command surface.

pub mod budget;
pub mod dedupe;
pub mod fanout;
pub mod manifest;
pub mod map_artifacts;
pub mod patch_edits;
pub mod prompt_spine;
pub mod runtime;
pub mod untrusted;
pub mod validator_catalogs;
pub mod verdict_chain;
pub mod votes;

pub use budget::{confirm_vote_degradation, BudgetDecision, BudgetDegradation, RunbookBudget};
pub use dedupe::{DedupeCluster, DedupeClusterArtifact, DedupeMethod};
pub use fanout::{
    CompletedWorkItem, FailedWorkItem, FanoutOutcome, PartialFailurePolicy, WorkItem, WorkItemKey,
};
pub use manifest::{EngagementPhase, RunbookManifest, RunbookStepKind, RunbookStepManifest};
pub use map_artifacts::{FocusArea, MapRunbookOutput, OpenQuestion};
pub use patch_edits::{
    PatchAuthorOutput, PatchDecision, PatchReviewDecision, PatchReviewOutput, StructuredPatchEdit,
};
pub use runtime::RunbookRuntime;
pub use untrusted::{
    decode_untrusted_record, render_untrusted_data_section, render_untrusted_derived_block,
    render_untrusted_repo_block, render_untrusted_repo_blocks, UntrustedRecord,
    UntrustedRecordKind,
};
pub use validator_catalogs::{validator_catalog, ValidatorCatalogKind};
pub use verdict_chain::{SnippetShown, VerdictChainArtifact, VerifierVoteRecord};
pub use votes::{
    tally_votes, ConfirmFinalVerdict, ConfirmVoteVerdict, NoiseTolerance, VerifierPromptVariant,
    VerifierVoteConfig, VotePlan, VoteTally,
};
