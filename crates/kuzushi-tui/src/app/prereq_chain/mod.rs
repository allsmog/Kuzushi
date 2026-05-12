use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrereqStep {
    pub tool: String,
    pub artifact_path: PathBuf,
    pub artifact_label: String,
    pub writes: Vec<PathBuf>,
    pub model_backed: bool,
    pub expensive: bool,
    pub risk: String,
    pub cost_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPrereqPrompt {
    pub final_tool: String,
    pub steps: Vec<PrereqPlanStep>,
    pub recommended_action: PrereqPlanAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrereqPlanStep {
    pub tool: String,
    pub artifact_path: PathBuf,
    pub artifact_label: String,
    pub artifact_state: PrereqArtifactState,
    pub writes: Vec<PathBuf>,
    pub model_backed: bool,
    pub expensive: bool,
    pub risk: String,
    pub cost_hint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrereqArtifactState {
    Cached,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrereqPlanAction {
    Approve,
    Reuse,
    Regenerate,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrereqChain {
    pub remaining: Vec<PrereqStep>,
    pub final_tool: String,
    pub final_input: Value,
    pub final_thinking_level: Option<String>,
    pub running_step: Option<String>,
    pub final_dispatched: bool,
    pub approved: bool,
    pub regenerate_existing: bool,
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
            approved: false,
            regenerate_existing: false,
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

    pub fn plan(&self) -> PendingPrereqPrompt {
        PendingPrereqPrompt {
            final_tool: self.final_tool.clone(),
            steps: self
                .remaining
                .iter()
                .map(PrereqPlanStep::from_step)
                .collect(),
            recommended_action: recommended_action(&self.remaining),
        }
    }

    pub fn should_run_step(&self, step: &PrereqStep) -> bool {
        self.regenerate_existing || !step.artifact_path.exists()
    }
}

impl PrereqStep {
    fn new(
        tool: &str,
        artifact_path: PathBuf,
        artifact_label: &str,
        model_backed: bool,
        expensive: bool,
        risk: &str,
        cost_hint: &str,
    ) -> Self {
        Self {
            tool: tool.to_string(),
            writes: vec![artifact_path.clone()],
            artifact_path,
            artifact_label: artifact_label.to_string(),
            model_backed,
            expensive,
            risk: risk.to_string(),
            cost_hint: cost_hint.to_string(),
        }
    }
}

impl PrereqPlanStep {
    fn from_step(step: &PrereqStep) -> Self {
        Self {
            tool: step.tool.clone(),
            artifact_path: step.artifact_path.clone(),
            artifact_label: step.artifact_label.clone(),
            artifact_state: artifact_state(&step.artifact_path),
            writes: step.writes.clone(),
            model_backed: step.model_backed,
            expensive: step.expensive,
            risk: step.risk.clone(),
            cost_hint: step.cost_hint.clone(),
        }
    }
}

impl PrereqArtifactState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Missing => "missing",
        }
    }
}

impl PrereqPlanAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reuse => "reuse",
            Self::Regenerate => "regenerate",
            Self::Cancel => "cancel",
        }
    }
}

fn artifact_state(path: &Path) -> PrereqArtifactState {
    if path.exists() {
        PrereqArtifactState::Cached
    } else {
        PrereqArtifactState::Missing
    }
}

fn recommended_action(steps: &[PrereqStep]) -> PrereqPlanAction {
    if steps.iter().all(|step| step.artifact_path.exists()) {
        PrereqPlanAction::Reuse
    } else {
        PrereqPlanAction::Approve
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
    if tool == "taint-iris-next:catalog" {
        return vec![context_step(&kuzushi_dir)];
    }
    if tool == "taint-iris-next:hunt" {
        // Hunt depends on context, and prefers a target-specific catalog
        // when available. We surface the catalog as a prereq so the
        // shell offers `reuse [r] / regenerate [g]` against an existing
        // <target>/.kuzushi/taint-iris-next-catalog.json. Operators who
        // want to skip catalog generation can answer "r" (or never run
        // catalog and just remove the file) — the hunt still runs with
        // the static built-in catalog as a fallback.
        return vec![context_step(&kuzushi_dir), taint_catalog_step(&kuzushi_dir)];
    }
    if matches!(tool, "taint-iris:hunt" | "agentic-sast:scan" | "sast:scan") {
        return vec![context_step(&kuzushi_dir)];
    }
    Vec::new()
}

fn context_step(kuzushi_dir: &Path) -> PrereqStep {
    PrereqStep::new(
        "context:build",
        kuzushi_dir.join("context-snapshot.json"),
        "context snapshot",
        false,
        false,
        "local repository indexing; filesystem read plus .kuzushi artifact write",
        "no model cost expected",
    )
}

fn taint_catalog_step(kuzushi_dir: &Path) -> PrereqStep {
    PrereqStep::new(
        "taint-iris-next:catalog",
        kuzushi_dir.join("taint-iris-next-catalog.json"),
        "taint-iris-next catalog",
        true,
        true,
        "model-backed catalog generation; writes a target-specific taint catalog artifact",
        "token cost unknown until the provider returns usage",
    )
}

fn threat_model_step(kuzushi_dir: &Path) -> PrereqStep {
    PrereqStep::new(
        "threat-model:build",
        kuzushi_dir.join("threat-model.json"),
        "threat model",
        true,
        true,
        "model-backed analysis; may spend tokens and writes a .kuzushi artifact",
        "token cost unknown until the provider returns usage",
    )
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

    #[test]
    fn taint_iris_next_hunt_chain_is_context_then_per_target_catalog() {
        let steps = prereq_steps_for("taint-iris-next:hunt", Path::new("/tmp/repo"));
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tool, "context:build");
        assert!(steps[0]
            .artifact_path
            .ends_with(".kuzushi/context-snapshot.json"));
        assert_eq!(steps[1].tool, "taint-iris-next:catalog");
        assert!(steps[1]
            .artifact_path
            .ends_with(".kuzushi/taint-iris-next-catalog.json"));
    }

    #[test]
    fn taint_iris_next_catalog_chain_includes_context() {
        let steps = prereq_steps_for("taint-iris-next:catalog", Path::new("/tmp/repo"));
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool, "context:build");
    }

    #[test]
    fn sast_pipeline_chain_includes_context() {
        let steps = prereq_steps_for("sast:scan", Path::new("/tmp/repo"));
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool, "context:build");
    }
}
