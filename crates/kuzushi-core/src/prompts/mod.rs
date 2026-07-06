//! Shared prompt spine for Kuzushi's agentic security prompts.
//!
//! This module is the single source of truth for the reusable prompt blocks
//! (attacker methodology, false-positive taxonomy, confidence calibration,
//! empty-findings legitimacy, output contract) and for the untrusted-repository
//! trust boundary that wraps every repository snippet copied into a prompt.
//!
//! Prompt-building code in each capability assembles prompts from these blocks
//! instead of inlining its own variant. See
//! `docs/agentic-prompt-hardening-design.md` for the design rationale.

pub mod boundaries;
pub mod prompt_render;
pub mod spine;
pub mod taxonomy;
pub mod validator_catalogs;

pub use boundaries::{
    render_untrusted_many, render_untrusted_repo_block, UNTRUSTED_REPO_BOUNDARY_INSTRUCTION,
    UNTRUSTED_REPO_END, UNTRUSTED_REPO_BEGIN,
};
pub use prompt_render::assemble_system_prompt;
pub use spine::{
    ATTACKER_METHODOLOGY, CONFIDENCE_CALIBRATION, EMPTY_FINDINGS_OK, OUTPUT_CONTRACT,
};
pub use taxonomy::FALSE_POSITIVE_TAXONOMY;
pub use validator_catalogs::{centralized_validator_catalog, PromptLanguage};

/// Version of the shared prompt spine. Bump whenever any spine block, boundary
/// instruction, taxonomy, or validator catalog changes so run artifacts can
/// record which prompt generation produced a finding.
pub const PROMPT_SPINE_VERSION: &str = "1";
