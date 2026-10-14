//! Versioned operator intent, separate from source evidence and model prompts.
mod binding;
mod domain;
mod guidance;
mod storage;
mod tool;
pub use binding::load_plan_brief;
pub(super) use binding::{attach, from_input, validate_plan};
pub use domain::{
    BriefDocument, BriefGuidanceV1, BriefReference, BriefRevision, MAX_BRIEF_TEXT_BYTES,
};
pub(super) use guidance::{guidance_receipt, prepare_guided_input};
use storage::save_brief;
pub use storage::{load_brief, load_current_brief};
pub use tool::execute_brief;

use anyhow::{Context, Result};
use std::path::Path;

#[cfg(test)]
mod tests;
