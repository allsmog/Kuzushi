use crate::{RuntimeRequirement, ToolPhase};
use serde::{Deserialize, Serialize};

/// Observable side effects a tool may have outside its return value.
///
/// This travels with `ToolDescriptor` so authorization never has to infer
/// safety from a module-name prefix at dispatch time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ToolEffect {
    /// Reads operator or workspace state without persisting a product artifact.
    Read,
    /// Writes Kuzushi-owned state under the active workspace.
    #[default]
    WorkspaceWrite,
    /// Modifies files that belong to the target repository.
    TargetWrite,
    /// Executes repository-selected commands in an isolated validation copy.
    RepositoryExecute,
    /// Acts on an external host or service.
    ExternalAction,
}

impl ToolEffect {
    pub const fn needs_operator_approval(self) -> bool {
        matches!(
            self,
            Self::TargetWrite | Self::RepositoryExecute | Self::ExternalAction
        )
    }
}

/// Authorization required before a descriptor may be dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalPolicy {
    #[default]
    None,
    /// An explicit headless invocation or an interactive approval is required.
    Explicit,
}

/// Whether execution requires an active, canonical workspace capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceRequirement {
    #[default]
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStoreRequirement {
    #[default]
    Optional,
    Required,
}

/// Complete dispatch policy declared beside a built-in descriptor.
///
/// The constructor derives approval from effect so target writes and external
/// actions cannot accidentally be declared without consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolPolicy {
    pub phase: ToolPhase,
    pub runtime_requirement: RuntimeRequirement,
    pub effect: ToolEffect,
    pub approval: ApprovalPolicy,
    pub workspace_requirement: WorkspaceRequirement,
    pub finding_store_requirement: FindingStoreRequirement,
}

impl ToolPolicy {
    pub const fn new(
        phase: ToolPhase,
        runtime_requirement: RuntimeRequirement,
        effect: ToolEffect,
        workspace_requirement: WorkspaceRequirement,
        finding_store_requirement: FindingStoreRequirement,
    ) -> Self {
        let approval = if effect.needs_operator_approval() {
            ApprovalPolicy::Explicit
        } else {
            ApprovalPolicy::None
        };
        Self {
            phase,
            runtime_requirement,
            effect,
            approval,
            workspace_requirement,
            finding_store_requirement,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_effects_derive_explicit_approval() {
        for effect in [
            ToolEffect::TargetWrite,
            ToolEffect::RepositoryExecute,
            ToolEffect::ExternalAction,
        ] {
            let policy = ToolPolicy::new(
                ToolPhase::Fix,
                RuntimeRequirement::Never,
                effect,
                WorkspaceRequirement::Required,
                FindingStoreRequirement::Optional,
            );
            assert_eq!(policy.approval, ApprovalPolicy::Explicit);
        }
    }
}
