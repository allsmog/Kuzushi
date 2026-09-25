use super::*;

impl SastPipelineReports {
    pub(in crate::modules) fn run_ids(&self, primary: String) -> SastRunIds {
        SastRunIds {
            primary,
            native: self.native_run_id(),
            agentic: self.agentic_run_id(),
            carlini: self.carlini_run_id(),
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

pub(in crate::modules) fn prepare_sast_task_selection(input: &Value) -> Result<SastTaskSelection> {
    let request = parse_sast_tasks(input)?;
    SastTaskSelection::from_tasks(request.tasks, request.source)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::modules) fn run_selected_sast_pipeline_reports(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    workspace: &crate::workspace::WorkspaceTarget,
    store: &crate::findings::FindingStore,
    options: &ScanRunOptions,
    selected: &SastTaskSelection,
) -> Result<SastPipelineReports> {
    selected.ensure_non_empty()?;
    let native = selected.run_native(workspace, store, options, ctx)?;
    let mut reports = initial_sast_pipeline_reports(selected, native);
    fill_agentic_reports(
        registry,
        option_store,
        &mut reports,
        selected,
        input,
        ctx,
        runtime,
    )?;
    Ok(reports)
}

fn initial_sast_pipeline_reports(
    selected: &SastTaskSelection,
    native: Option<ScanRun>,
) -> SastPipelineReports {
    let engine_outcomes = selected
        .engine_ids
        .iter()
        .map(|engine| {
            (
                *engine,
                crate::run_artifacts::ScanEngineStageOutcome::Complete,
            )
        })
        .collect();
    SastPipelineReports {
        native,
        agentic: None,
        carlini: None,
        taint_iris_next: None,
        systems_hunt: None,
        engine_ids: selected.engine_ids.clone(),
        engine_outcomes,
        skipped_engines: selected.skipped_engines.clone(),
        engine_skip_reasons: Default::default(),
    }
}

pub(in crate::modules) struct SastTaskSelection {
    pub(in crate::modules) scanners: Vec<Box<dyn ScanEngine>>,
    pub(in crate::modules) explicit_native_selection: bool,
    pub(in crate::modules) run_agentic: bool,
    pub(in crate::modules) run_carlini: bool,
    pub(in crate::modules) run_taint_iris_next: bool,
    pub(in crate::modules) run_systems_hunt: bool,
    pub(in crate::modules) engine_ids: Vec<&'static str>,
    pub(in crate::modules) skipped_engines: Vec<crate::scan::SkippedDefaultScanEngine>,
}
