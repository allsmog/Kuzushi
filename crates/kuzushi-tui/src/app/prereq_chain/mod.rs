use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrereqStep {
    pub tool: String,
    pub artifact_path: PathBuf,
    pub artifact_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPrereqPrompt {
    pub current_tool: String,
    pub current_artifact_path: PathBuf,
    pub current_artifact_label: String,
    pub final_tool: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrereqChain {
    pub remaining: Vec<PrereqStep>,
    pub final_tool: String,
    pub final_input: Value,
    pub final_thinking_level: Option<String>,
    pub running_step: Option<String>,
    pub final_dispatched: bool,
}

impl PrereqChain {
    pub fn new(
        steps: Vec<PrereqStep>,
        final_tool: String,
        final_input: Value,
        final_thinking_level: Option<String>,
    ) -> Self {
        Self {
            remaining: steps,
            final_tool,
            final_input,
            final_thinking_level,
            running_step: None,
            final_dispatched: false,
        }
    }

    pub fn next_step(&self) -> Option<&PrereqStep> {
        self.remaining.first()
    }

    pub fn drop_first(&mut self) -> Option<PrereqStep> {
        if self.remaining.is_empty() {
            None
        } else {
            Some(self.remaining.remove(0))
        }
    }
}

pub fn prereq_steps_for(tool: &str, target: &Path) -> Vec<PrereqStep> {
    let kuzushi_dir = target.join(".kuzushi");
    if tool == "carlini-threat-hunt:run" {
        return vec![context_step(&kuzushi_dir), threat_model_step(&kuzushi_dir)];
    }
    if tool == "threat-model:build" {
        return vec![context_step(&kuzushi_dir)];
    }
    Vec::new()
}

fn context_step(kuzushi_dir: &Path) -> PrereqStep {
    PrereqStep {
        tool: "context:build".to_string(),
        artifact_path: kuzushi_dir.join("context-snapshot.json"),
        artifact_label: "context snapshot".to_string(),
    }
}

fn threat_model_step(kuzushi_dir: &Path) -> PrereqStep {
    PrereqStep {
        tool: "threat-model:build".to_string(),
        artifact_path: kuzushi_dir.join("threat-model.json"),
        artifact_label: "threat model".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carlini_chain_includes_context_then_threat_model() {
        let steps = prereq_steps_for("carlini-threat-hunt:run", Path::new("/tmp/repo"));
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tool, "context:build");
        assert_eq!(steps[1].tool, "threat-model:build");
        assert!(steps[0]
            .artifact_path
            .ends_with(".kuzushi/context-snapshot.json"));
        assert!(steps[1]
            .artifact_path
            .ends_with(".kuzushi/threat-model.json"));
    }

    #[test]
    fn unknown_tool_has_no_prereqs() {
        let steps = prereq_steps_for("findings:list", Path::new("/tmp/repo"));
        assert!(steps.is_empty());
    }
}
