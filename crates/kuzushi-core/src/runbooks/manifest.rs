use anyhow::{ensure, Result};

/// Engagement phase represented in core so tools can emit phase-aware
/// checkpoints without depending on the TUI's onboarding module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EngagementPhase {
    Map,
    Hunt,
    Confirm,
    Fix,
}

impl EngagementPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Map => "map",
            Self::Hunt => "hunt",
            Self::Confirm => "confirm",
            Self::Fix => "fix",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunbookStepKind {
    Deterministic,
    ModelCall,
    Fanout,
    ToolCall,
    Join,
    Persist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunbookStepManifest {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: RunbookStepKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunbookManifest {
    pub id: &'static str,
    pub version: &'static str,
    pub phase: EngagementPhase,
    pub owner_tool: &'static str,
    pub title: &'static str,
    pub steps: &'static [RunbookStepManifest],
    pub output_schema_version: &'static str,
}

impl RunbookManifest {
    pub fn has_step(&self, step_id: &str) -> bool {
        self.steps.iter().any(|step| step.id == step_id)
    }

    pub fn step_label(&self, step_id: &str) -> Option<&'static str> {
        self.steps
            .iter()
            .find(|step| step.id == step_id)
            .map(|step| step.label)
    }

    pub fn assert_step(&self, step_id: &str) -> Result<()> {
        ensure!(
            self.has_step(step_id),
            "runbook {} emitted unknown step id {:?}",
            self.id,
            step_id
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEPS: &[RunbookStepManifest] = &[
        RunbookStepManifest {
            id: "scope",
            label: "scope target",
            kind: RunbookStepKind::Deterministic,
        },
        RunbookStepManifest {
            id: "review",
            label: "review focus areas",
            kind: RunbookStepKind::Fanout,
        },
    ];

    const MANIFEST: RunbookManifest = RunbookManifest {
        id: "hunt-agentic-sast",
        version: "test",
        phase: EngagementPhase::Hunt,
        owner_tool: "agentic-sast:scan",
        title: "Agentic SAST hunt",
        steps: STEPS,
        output_schema_version: "test.v1",
    };

    #[test]
    fn manifest_validates_step_ids() {
        assert!(MANIFEST.assert_step("scope").is_ok());
        assert!(MANIFEST.assert_step("missing").is_err());
        assert_eq!(MANIFEST.step_label("review"), Some("review focus areas"));
    }
}
