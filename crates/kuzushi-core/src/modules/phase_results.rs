use super::autonomy::{classify_descriptor, ToolClassification};
use super::ToolDescriptor;
use crate::WorkflowPhase;

/// Result ownership is separate from the phase used to authorize execution.
pub fn phase_result_phase(tool: &ToolDescriptor) -> Option<WorkflowPhase> {
    if !tool.phase_result {
        return None;
    }
    match classify_descriptor(tool) {
        Some(ToolClassification::Phase(phase)) => Some(phase),
        Some(ToolClassification::Read) | None => None,
    }
}

#[cfg(test)]
mod tests;
