use super::*;

impl SastPipelineReports {
    pub(in crate::modules) fn findings_count(&self) -> usize {
        self.native.as_ref().map_or(0, |run| run.findings_count)
            + self.agentic.as_ref().map_or(0, |report| report.count)
            + self.carlini.as_ref().map_or(0, |report| report.count)
            + self.taint_iris.as_ref().map_or(0, |report| report.count)
            + self
                .taint_iris_next
                .as_ref()
                .map_or(0, |report| report.count)
            + self.systems_hunt.as_ref().map_or(0, |report| report.count)
    }

    pub(in crate::modules) fn primary_run_id(&self) -> Result<String> {
        self.native_run_id()
            .or_else(|| self.agentic_run_id())
            .or_else(|| self.carlini_run_id())
            .or_else(|| self.taint_iris_run_id())
            .or_else(|| self.taint_iris_next_run_id())
            .or_else(|| self.systems_hunt_run_id())
            .context("sast:scan completed without a persisted run id")
    }

    pub(in crate::modules) fn run_ids(&self, primary: String) -> SastRunIds {
        SastRunIds {
            primary,
            native: self.native_run_id(),
            agentic: self.agentic_run_id(),
            carlini: self.carlini_run_id(),
            taint_iris: self.taint_iris_run_id(),
            taint_iris_next: self.taint_iris_next_run_id(),
            systems_hunt: self.systems_hunt_run_id(),
        }
    }

    pub(in crate::modules) fn native_run_id(&self) -> Option<String> {
        self.native.as_ref().map(|run| run.id.clone())
    }

    pub(in crate::modules) fn agentic_run_id(&self) -> Option<String> {
        self.agentic
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    pub(in crate::modules) fn carlini_run_id(&self) -> Option<String> {
        self.carlini
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    pub(in crate::modules) fn taint_iris_run_id(&self) -> Option<String> {
        self.taint_iris
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    pub(in crate::modules) fn taint_iris_next_run_id(&self) -> Option<String> {
        self.taint_iris_next
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    pub(in crate::modules) fn systems_hunt_run_id(&self) -> Option<String> {
        self.systems_hunt
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }
}

pub(in crate::modules) fn run_sast_pipeline_reports(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    workspace: &crate::workspace::WorkspaceTarget,
    store: &crate::findings::FindingStore,
    options: &ScanRunOptions,
) -> Result<SastPipelineReports> {
    let tasks = parse_sast_tasks(input)?;
    let selected = SastTaskSelection::from_tasks(tasks)?;
    selected.ensure_non_empty()?;
    let mut reports = SastPipelineReports {
        native: selected.run_native(workspace, store, options)?,
        agentic: None,
        carlini: None,
        taint_iris: None,
        taint_iris_next: None,
        systems_hunt: None,
        engine_ids: selected.engine_ids.clone(),
    };
    fill_agentic_reports(&mut reports, &selected, input, ctx, runtime)?;
    Ok(reports)
}

pub(in crate::modules) struct SastTaskSelection {
    pub(in crate::modules) scanners: Vec<Box<dyn ScanEngine>>,
    pub(in crate::modules) run_agentic: bool,
    pub(in crate::modules) run_carlini: bool,
    pub(in crate::modules) run_taint_iris: bool,
    pub(in crate::modules) run_taint_iris_next: bool,
    pub(in crate::modules) run_systems_hunt: bool,
    pub(in crate::modules) engine_ids: Vec<&'static str>,
}
