//! Code-first phase runbooks for app-orchestrated LLM workflows.
//!
//! The TUI keeps dispatching ordinary tools (`agentic-sast:scan`, `triage:run`,
//! `patch:finding`, ...). Tool implementations can opt into these runbook
//! helpers to get stable phase/step labels, checkpoint artifacts, fanout
//! bookkeeping, and shared prompt hardening without introducing a second
//! user-facing command surface.

pub mod fanout;
pub mod manifest;
pub mod prompt_spine;
pub mod runtime;
pub mod untrusted;

pub use fanout::{CompletedWorkItem, FailedWorkItem, FanoutOutcome, PartialFailurePolicy, WorkItem, WorkItemKey};
pub use manifest::{EngagementPhase, RunbookManifest, RunbookStepKind, RunbookStepManifest};
pub use runtime::RunbookRuntime;
pub use untrusted::{render_untrusted_derived_block, render_untrusted_repo_block, render_untrusted_repo_blocks};
