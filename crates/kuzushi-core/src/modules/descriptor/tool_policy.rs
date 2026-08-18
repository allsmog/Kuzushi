use super::{RuntimeRequirement, ToolPhase};

pub use kuzushi_descriptor::{
    ApprovalPolicy, FindingStoreRequirement, ToolEffect, ToolPolicy, WorkspaceRequirement,
};

pub(in crate::modules) const fn tool_policy(
    phase: ToolPhase,
    runtime_requirement: RuntimeRequirement,
    effect: ToolEffect,
    workspace_requirement: WorkspaceRequirement,
    finding_store_requirement: FindingStoreRequirement,
) -> ToolPolicy {
    ToolPolicy::new(
        phase,
        runtime_requirement,
        effect,
        workspace_requirement,
        finding_store_requirement,
    )
}

pub(in crate::modules) const fn workspace_policy(
    phase: ToolPhase,
    runtime_requirement: RuntimeRequirement,
    finding_store_requirement: FindingStoreRequirement,
) -> ToolPolicy {
    ToolPolicy::new(
        phase,
        runtime_requirement,
        ToolEffect::WorkspaceWrite,
        WorkspaceRequirement::Required,
        finding_store_requirement,
    )
}

pub(in crate::modules) const fn read_policy(
    phase: ToolPhase,
    workspace_requirement: WorkspaceRequirement,
) -> ToolPolicy {
    ToolPolicy::new(
        phase,
        RuntimeRequirement::Never,
        ToolEffect::Read,
        workspace_requirement,
        FindingStoreRequirement::Optional,
    )
}

pub(in crate::modules) const fn target_write_policy(
    phase: ToolPhase,
    runtime_requirement: RuntimeRequirement,
    finding_store_requirement: FindingStoreRequirement,
) -> ToolPolicy {
    ToolPolicy::new(
        phase,
        runtime_requirement,
        ToolEffect::TargetWrite,
        WorkspaceRequirement::Required,
        finding_store_requirement,
    )
}

pub(in crate::modules) const fn repository_execute_policy(
    phase: ToolPhase,
    runtime_requirement: RuntimeRequirement,
    finding_store_requirement: FindingStoreRequirement,
) -> ToolPolicy {
    ToolPolicy::new(
        phase,
        runtime_requirement,
        ToolEffect::RepositoryExecute,
        WorkspaceRequirement::Required,
        finding_store_requirement,
    )
}

pub(in crate::modules) const fn external_action_policy(
    phase: ToolPhase,
    runtime_requirement: RuntimeRequirement,
    finding_store_requirement: FindingStoreRequirement,
) -> ToolPolicy {
    ToolPolicy::new(
        phase,
        runtime_requirement,
        ToolEffect::ExternalAction,
        WorkspaceRequirement::Required,
        finding_store_requirement,
    )
}
