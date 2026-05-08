pub(in crate::renderer) use super::*;

/// Returns a one-word stage label when the shell has a long-running
/// worker active (scan / agent / planner / threats).  None when idle —
/// in which case the top status strip skips the `stage ⠿ …` segment.
pub(in crate::renderer) use active_stage_label::*;
pub(in crate::renderer) use context_strip::*;
mod active_stage_label;
mod context_strip;
pub(crate) use active_stage_label::active_stage_label;
pub(crate) use context_strip::context_strip;
