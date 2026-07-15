use super::WorkflowPhase;
use crate::modules::descriptor::{ToolDescriptor, ToolEffect, ToolPhase};

/// How a descriptor relates to the engagement spine for autonomy gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClassification {
    Read,
    Phase(WorkflowPhase),
}

/// Descriptor-owned classification used by the shared dispatch boundary.
pub fn classify_descriptor(tool: &ToolDescriptor) -> Option<ToolClassification> {
    if tool.effect == ToolEffect::Read {
        return Some(ToolClassification::Read);
    }
    workflow_phase(tool.phase).map(ToolClassification::Phase)
}

/// Compatibility lookup for shell presentation. Built-ins are resolved from
/// their registered descriptor, so this cannot drift from dispatch policy.
pub fn classify(tool_name: &str) -> Option<ToolClassification> {
    let registry = crate::modules::registry::ModuleRegistry::with_v2_builtins();
    registry
        .resolve_tool(tool_name)
        .and_then(classify_descriptor)
}

pub fn tool_phase(tool_name: &str) -> Option<WorkflowPhase> {
    match classify(tool_name) {
        Some(ToolClassification::Phase(phase)) => Some(phase),
        Some(ToolClassification::Read) | None => None,
    }
}

pub fn tool_mutates(tool_name: &str) -> bool {
    let registry = crate::modules::registry::ModuleRegistry::with_v2_builtins();
    registry
        .resolve_tool(tool_name)
        .is_some_and(|tool| tool.effect.needs_operator_approval())
}

fn workflow_phase(phase: ToolPhase) -> Option<WorkflowPhase> {
    match phase {
        ToolPhase::Map => Some(WorkflowPhase::Map),
        ToolPhase::Scan => Some(WorkflowPhase::Scan),
        ToolPhase::Review => Some(WorkflowPhase::Review),
        ToolPhase::Prove => Some(WorkflowPhase::Prove),
        ToolPhase::Fix => Some(WorkflowPhase::Fix),
        ToolPhase::Operate => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_descriptor_drives_phase_and_effect() {
        assert_eq!(tool_phase("context:build"), Some(WorkflowPhase::Map));
        assert_eq!(tool_phase("semgrep:scan"), Some(WorkflowPhase::Scan));
        assert_eq!(tool_phase("triage:run"), Some(WorkflowPhase::Review));
        assert_eq!(
            tool_phase("classifier-gate:score"),
            Some(WorkflowPhase::Review)
        );
        assert_eq!(tool_phase("deep-audit:run"), Some(WorkflowPhase::Review));
        assert_eq!(tool_phase("verify:finding"), Some(WorkflowPhase::Prove));
        assert_eq!(tool_phase("patch:finding"), Some(WorkflowPhase::Fix));
        assert_eq!(tool_phase("prompt-armor:report"), Some(WorkflowPhase::Fix));
        assert_eq!(classify("findings:list"), Some(ToolClassification::Read));
        assert!(tool_mutates("patch:finding"));
        assert!(!tool_mutates("findings:dismiss"));
    }

    #[test]
    fn unknown_tool_has_no_compatibility_classification() {
        assert_eq!(classify("brand-new-module:do-thing"), None);
    }
}
