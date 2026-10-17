use super::*;

impl SastTaskSelection {
    pub(in crate::modules) fn configure_cargo_audit(&mut self, input: &Value) -> Result<()> {
        let options = crate::modules::native_scanners::cargo_audit_settings(input);
        let selected = self
            .scanners
            .iter()
            .any(|scanner| scanner.id() == "cargo-audit");
        anyhow::ensure!(options.as_object().unwrap().is_empty() || selected, "Cargo audit options require the cargo-audit task. Clear them or select that task explicitly.");
        for scanner in &mut self.scanners {
            if scanner.id() == "cargo-audit" {
                *scanner = Box::new(
                    crate::dep_hygiene::ConfiguredCargoAuditScanner::from_tool_input(&options)?,
                );
            }
        }
        Ok(())
    }
    pub(in crate::modules) fn configure_iac_scan(&mut self, input: &Value) -> Result<()> {
        let settings = iac_scan_settings(input);
        let selected = self
            .scanners
            .iter()
            .any(|scanner| scanner.id() == "iac-scan");
        anyhow::ensure!(settings.as_object().unwrap().is_empty() || selected, "IaC inspection options require the iac-scan task. Clear them or select that task explicitly.");
        for scanner in &mut self.scanners {
            if scanner.id() == "iac-scan" {
                *scanner = Box::new(crate::iac_scan::ConfiguredIacScanScanner::new(
                    crate::iac_scan::IacScanOptions::from_tool_input(&settings)?,
                ));
            }
        }
        Ok(())
    }
    pub(in crate::modules) fn configure_secret_scan(&mut self, input: &Value) -> Result<()> {
        let settings = secret_scan_settings(input);
        let selected = self
            .scanners
            .iter()
            .any(|scanner| scanner.id() == "secret-scan");
        anyhow::ensure!(settings.as_object().unwrap().is_empty() || selected,
            "Secret inspection options require the secret-scan task. Clear those options or explicitly select that task.");
        for scanner in &mut self.scanners {
            if scanner.id() == "secret-scan" {
                *scanner = Box::new(crate::secret_scan::ConfiguredSecretScanScanner::new(
                    crate::secret_scan::SecretScanOptions::from_tool_input(&settings)?,
                ));
            }
        }
        Ok(())
    }
    pub(in crate::modules) fn configure_semgrep(&mut self, input: &Value) -> Result<()> {
        let options = semgrep_settings(input);
        let selected = self
            .scanners
            .iter()
            .any(|scanner| scanner.id() == "semgrep");
        anyhow::ensure!(
            options.as_object().unwrap().is_empty() || selected,
            "Semgrep options require the semgrep task. Clear them or select that task explicitly."
        );
        for scanner in &mut self.scanners {
            if scanner.id() == "semgrep" {
                *scanner = Box::new(crate::scan::ConfiguredSemgrepScanner::from_tool_input(
                    &options,
                )?);
            }
        }
        Ok(())
    }
    pub(in crate::modules) fn planned_engine_ids(&self) -> Vec<String> {
        let mut engines = self
            .engine_ids
            .iter()
            .map(|engine| (*engine).to_string())
            .collect::<Vec<_>>();
        for (selected, engine) in [
            (self.run_agentic, "agentic"),
            (self.run_carlini, "offense-review"),
            (self.run_taint_iris_next, "taint-iris-next"),
            (self.run_systems_hunt, "systems-hunt"),
        ] {
            if selected {
                engines.push(engine.to_string());
            }
        }
        engines.extend(
            self.skipped_engines
                .iter()
                .map(|engine| engine.id.to_string()),
        );
        engines
    }

    pub(in crate::modules) fn from_tasks(
        tasks: Vec<String>,
        source: SastTaskSelectionSource,
    ) -> Result<Self> {
        crate::capabilities::agentic_sast::validate_sast_stage_aliases(&tasks)?;
        let (native_tasks, run_agentic, run_carlini, run_taint_iris_next, run_systems_hunt) =
            split_agentic_sast_tasks(tasks);
        let explicit_native_selection =
            source == SastTaskSelectionSource::Explicit && !native_tasks.is_empty();
        let native = selected_native_scanners(
            &native_tasks,
            run_agentic || run_carlini || run_taint_iris_next || run_systems_hunt,
            source,
        )?;
        let engine_ids = native
            .engines
            .iter()
            .map(|scanner| scanner.id())
            .collect::<Vec<_>>();
        Ok(Self {
            scanners: native.engines,
            skipped_engines: native.skipped,
            explicit_native_selection,
            run_agentic,
            run_carlini,
            run_taint_iris_next,
            run_systems_hunt,
            engine_ids,
        })
    }

    pub(in crate::modules) fn ensure_non_empty(&self) -> Result<()> {
        if self.scanners.is_empty() && !self.has_agentic_task() {
            anyhow::bail!("sast:scan selected no scan engines");
        }
        Ok(())
    }

    pub(in crate::modules) fn has_agentic_task(&self) -> bool {
        self.run_agentic || self.run_carlini || self.run_taint_iris_next || self.run_systems_hunt
    }

    pub(in crate::modules) fn run_native(
        &self,
        workspace: &crate::workspace::WorkspaceTarget,
        store: &crate::findings::FindingStore,
        options: &SastScanOptions,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Option<NativeScanReport>> {
        self.ensure_explicit_native_prerequisites(workspace, options)?;
        if self.scanners.is_empty() {
            Ok(None)
        } else {
            ctx.with_cancellation(|cancellation| {
                match options.discovery_files() {
                    Some(files) => run_native_scan_files_with_cancellation(
                        workspace,
                        store,
                        &self.scanners,
                        &options.run,
                        files,
                        cancellation,
                    ),
                    None => run_native_scan_with_cancellation(
                        workspace,
                        store,
                        &self.scanners,
                        &options.run,
                        cancellation,
                    ),
                }
                .map(Some)
            })
        }
    }

    fn ensure_explicit_native_prerequisites(
        &self,
        workspace: &crate::workspace::WorkspaceTarget,
        options: &SastScanOptions,
    ) -> Result<()> {
        if self.root_lockfile_required(options) && !workspace.root().join("Cargo.lock").is_file() {
            anyhow::bail!(
                "cargo-audit was explicitly requested, but the target has no Cargo.lock. Run `cargo generate-lockfile` in the target, then rerun the scan"
            );
        }
        Ok(())
    }

    fn root_lockfile_required(&self, options: &SastScanOptions) -> bool {
        self.explicit_native_selection
            && self.engine_ids.contains(&"cargo-audit")
            && options.run.paths.is_empty()
    }
}

fn secret_scan_settings(input: &Value) -> Value {
    let mut settings = serde_json::Map::new();
    for (parent, child) in [
        ("secretScanMaxFileBytes", "maxFileBytes"),
        ("secretScanMaxFindings", "maxFindings"),
        ("secretScanMaxEntries", "maxEntries"),
        ("secretScanMaxTotalBytes", "maxTotalBytes"),
    ] {
        if let Some(value) = input.get(parent) {
            settings.insert(child.into(), value.clone());
        }
    }
    Value::Object(settings)
}

fn iac_scan_settings(input: &Value) -> Value {
    let mut settings = serde_json::Map::new();
    for (parent, child) in [
        ("iacScanMaxFileBytes", "maxFileBytes"),
        ("iacScanMaxEntries", "maxEntries"),
        ("iacScanMaxTotalBytes", "maxTotalBytes"),
    ] {
        if let Some(value) = input.get(parent) {
            settings.insert(child.into(), value.clone());
        }
    }
    Value::Object(settings)
}

fn semgrep_settings(input: &Value) -> Value {
    let mut settings = serde_json::Map::new();
    for (parent, child) in [
        ("semgrepConfig", "config"),
        ("semgrepBinary", "binary"),
        ("semgrepJobs", "jobs"),
        ("semgrepTimeoutMs", "timeoutMs"),
    ] {
        if let Some(value) = input.get(parent).filter(|value| !value.is_null()) {
            settings.insert(child.into(), value.clone());
        }
    }
    Value::Object(settings)
}

pub(in crate::modules) fn selected_native_scanners(
    native_tasks: &[String],
    only_agentic_tasks: bool,
    source: SastTaskSelectionSource,
) -> Result<DefaultScanEngineSelection> {
    if native_tasks.is_empty() && only_agentic_tasks {
        return Ok(empty_scan_engine_selection());
    }
    match source {
        SastTaskSelectionSource::Automatic => select_default_scan_engines_checked(None),
        SastTaskSelectionSource::FilteredAutomatic => filtered_default_scan_engines(native_tasks),
        SastTaskSelectionSource::Explicit => explicit_native_scanners(native_tasks),
    }
}

fn explicit_native_scanners(native_tasks: &[String]) -> Result<DefaultScanEngineSelection> {
    if native_tasks.is_empty() {
        return Ok(empty_scan_engine_selection());
    }
    Ok(DefaultScanEngineSelection {
        engines: scan_engines_for_tasks(native_tasks)?,
        skipped: Vec::new(),
    })
}

fn empty_scan_engine_selection() -> DefaultScanEngineSelection {
    DefaultScanEngineSelection {
        engines: Vec::new(),
        skipped: Vec::new(),
    }
}

fn filtered_default_scan_engines(native_tasks: &[String]) -> Result<DefaultScanEngineSelection> {
    let mut selection = select_default_scan_engines_checked(Some(native_tasks))?;
    selection
        .engines
        .retain(|scanner| native_tasks.iter().any(|task| task == scanner.id()));
    selection
        .skipped
        .retain(|skipped| native_tasks.iter().any(|task| task == skipped.id));
    Ok(selection)
}

pub(in crate::modules) fn fill_agentic_reports(
    registry: &ModuleRegistry,
    option_store: &crate::options::ToolOptionStore,
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<()> {
    let dispatch = SastSubtoolDispatch {
        registry,
        option_store,
        input,
        ctx,
        runtime,
    };
    fill_agentic_sast_report(reports, selected, &dispatch)?;
    fill_offense_review_report(reports, selected, &dispatch)?;
    fill_taint_iris_next_report(reports, selected, &dispatch)?;
    fill_systems_hunt_report(reports, selected, &dispatch)
}

fn fill_agentic_sast_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_agentic {
        let input = agentic_scoped_input(dispatch.input);
        let run = dispatch.report_from_input("agentic-sast:scan", &input)?;
        reports.agentic = reports.record_engine("agentic", run);
    }
    Ok(())
}

fn fill_offense_review_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_carlini {
        let run = dispatch.report_from_data("offense-review:threat-hunt")?;
        reports.carlini = reports.record_engine("offense-review", run);
    }
    Ok(())
}

fn fill_taint_iris_next_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_taint_iris_next {
        reports.engine_ids.push("taint-iris-next");
        let (report, outcome) = dispatch.taint_iris_next_report()?;
        reports.engine_outcomes.insert("taint-iris-next", outcome);
        reports.taint_iris_next = Some(report);
    }
    Ok(())
}

fn fill_systems_hunt_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_systems_hunt {
        let run = dispatch.report_from_data("systems-hunt:systems-hunt")?;
        reports.systems_hunt = reports.record_engine("systems-hunt", run);
    }
    Ok(())
}

/// One dispatched engine: its parsed report (absent when it skipped), its
/// outcome, and the engine's own reason for a skip.
struct EngineRun<T> {
    report: Option<T>,
    outcome: crate::run_artifacts::ScanEngineStageOutcome,
    skip_reason: Option<String>,
    not_applicable: bool,
}

impl<T> EngineRun<T> {
    fn skipped(output: &Value) -> Self {
        Self {
            report: None,
            outcome: crate::run_artifacts::ScanEngineStageOutcome::Skipped,
            skip_reason: output
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string),
            not_applicable: output.pointer("/data/notApplicable") == Some(&Value::Bool(true)),
        }
    }
}

impl SastPipelineReports {
    fn record_engine<T>(&mut self, engine: &'static str, run: EngineRun<T>) -> Option<T> {
        self.engine_ids.push(engine);
        self.engine_outcomes.insert(engine, run.outcome);
        if let Some(reason) = run.skip_reason {
            self.engine_skip_reasons.insert(engine, reason);
        }
        if run.not_applicable {
            self.engines_not_applicable.insert(engine);
        }
        run.report
    }
}

struct SastSubtoolDispatch<'a> {
    registry: &'a ModuleRegistry,
    option_store: &'a crate::options::ToolOptionStore,
    input: &'a Value,
    ctx: &'a ToolExecutionContext<'a>,
    runtime: Option<&'a dyn AgentRuntime>,
}

impl SastSubtoolDispatch<'_> {
    fn report_from_data<T>(&self, tool_name: &str) -> Result<EngineRun<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        self.report_from_input(tool_name, self.input)
    }

    /// An engine that reports `skipped` (it does not apply to this target)
    /// has no report to parse; its outcome is still recorded.
    fn report_from_input<T>(&self, tool_name: &str, input: &Value) -> Result<EngineRun<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let output = self.checkpointed_engine_output(tool_name, input)?;
        let outcome = scan_engine_outcome(&output);
        if outcome == crate::run_artifacts::ScanEngineStageOutcome::Skipped {
            return Ok(EngineRun::skipped(&output));
        }
        let data = output
            .get("data")
            .cloned()
            .with_context(|| format!("{tool_name} output did not include data"))?;
        let report = serde_json::from_value(data)
            .with_context(|| format!("{tool_name} returned invalid report data"))?;
        Ok(EngineRun {
            report: Some(report),
            outcome,
            skip_reason: None,
            not_applicable: false,
        })
    }

    fn taint_iris_next_report(
        &self,
    ) -> Result<(
        TaintIrisNextReport,
        crate::run_artifacts::ScanEngineStageOutcome,
    )> {
        let tool_name = "taint-iris-next:hunt";
        let output =
            self.checkpointed_engine_output(tool_name, &self.taint_iris_next_scoped_input())?;
        let outcome = scan_engine_outcome(&output);
        Ok((taint_iris_next_report_from_tool_output(&output)?, outcome))
    }

    /// Umbrella-level engine continuation: a Completed agentic engine from a
    /// prior failed sast:scan run is reused from its checkpointed output.
    /// Its findings already live in the findings store; reusing the report
    /// never re-ingests them.
    /// taint-iris-next scopes by one `targetSubdir`: a scan scoped to exactly
    /// one directory passes it through. Scope validation rejects unsupported
    /// memberships before any engine starts.
    fn taint_iris_next_scoped_input(&self) -> Value {
        let mut input = taint_iris_next_hunt_input(self.input);
        let root = self.ctx.workspace.map(|workspace| workspace.root());
        if let Some(subdir) = single_scope_directory(self.input, root) {
            if let Some(object) = input.as_object_mut() {
                object.entry("targetSubdir").or_insert(json!(subdir));
            }
        }
        input
    }

    fn checkpointed_engine_output(&self, tool_name: &str, input: &Value) -> Result<Value> {
        let stage_id = format!("engine:{tool_name}");
        let checkpoints = crate::run_artifacts::active_stage_checkpoints();
        if let Some(output) = reuse_completed_engine_output(checkpoints.as_deref(), &stage_id) {
            return Ok(output);
        }
        let stage = checkpoints.as_deref().map(|handle| handle.stage(&stage_id));
        let output = self.run(tool_name, input)?;
        record_completed_engine_output(checkpoints.as_deref(), stage, &stage_id, &output);
        Ok(output)
    }

    fn run(&self, tool_name: &str, input: &Value) -> Result<Value> {
        let input = descriptor_filtered_input(self.registry, tool_name, input)?;
        let output = dispatch_scan_engine_with_run(
            self.registry,
            tool_name,
            input,
            self.ctx,
            self.runtime,
            self.option_store,
        )?;
        validate_sast_scan_engine_result(tool_name, &output)?;
        Ok(output)
    }
}

fn reuse_completed_engine_output(
    handle: Option<&crate::run_artifacts::StageCheckpointHandle>,
    stage_id: &str,
) -> Option<Value> {
    let handle = handle?;
    let receipt = handle.completed_stage(stage_id)?;
    let output = handle.read_stage_payload(&receipt)?;
    handle.record_reused_stage(
        stage_id,
        "reused completed engine output from prior failed run",
    );
    Some(output)
}

/// Only a Complete engine outcome is checkpoint-worthy; partial or failed
/// engines must re-run on continuation.
fn record_completed_engine_output(
    handle: Option<&crate::run_artifacts::StageCheckpointHandle>,
    stage: Option<crate::run_artifacts::StageGuard<'_>>,
    stage_id: &str,
    output: &Value,
) {
    if scan_engine_outcome(output) != crate::run_artifacts::ScanEngineStageOutcome::Complete {
        return;
    }
    if let (Some(handle), Some(stage)) = (handle, stage) {
        let artifacts = handle
            .write_stage_payload(stage_id, output)
            .into_iter()
            .collect();
        stage.complete(artifacts);
    }
}

fn dispatch_scan_engine_with_run(
    registry: &ModuleRegistry,
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("sast:scan child engine requires an active workspace")?;
    let run_id = crate::run_artifacts::new_run_id("scan-engine");
    let record =
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), &run_id, "tool", tool_name);
    start_scan_engine_run(registry, record, &input, ctx)?;
    let observation = start_scan_engine_observation(workspace.root(), &run_id, tool_name)?;
    let trace = observation.trace_handle();
    let child_ctx = ToolExecutionContext {
        config: ctx.config,
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
        trace: Some(&trace),
        cancellation: ctx.cancellation,
        authorization: ctx.authorization.clone(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool_name, input, &child_ctx, Some(option_store))?
        .authorize_delegated(&child_ctx.authorization);
    let dispatched =
        registry.dispatch_prepared_input_observed_with_runtime(prepared, &child_ctx, runtime)?;
    finish_scan_engine_run(record, dispatched, &observation)
}

fn start_scan_engine_observation(
    target: &std::path::Path,
    run_id: &str,
    tool_name: &str,
) -> Result<crate::run_lifecycle::RunObservationHandle> {
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(target, run_id)?
        .start_root_task(format!("Scan with {tool_name}"))?;
    observation
        .task_handle()
        .context("scan engine dispatch lacks its semantic task")?
        .update_and_flush(crate::run_lifecycle::RunItemStatus::Running, None)?;
    Ok(observation)
}

fn start_scan_engine_run(
    registry: &ModuleRegistry,
    record: crate::run_artifacts::ToolRunRecord<'_>,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let model = registry
        .tool_needs_runtime(record.tool, input)
        .then(|| ctx.config.model.clone())
        .flatten();
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        input,
        model,
        crate::config::config_hash(ctx.config).ok(),
        registry.loaded_module_specifiers(),
    )
}

fn finish_scan_engine_run(
    record: crate::run_artifacts::ToolRunRecord<'_>,
    dispatched: crate::modules::ObservedDispatchOutcome,
    observation: &crate::run_lifecycle::RunObservationHandle,
) -> Result<Value> {
    match dispatched.execution {
        Ok(output) => {
            crate::run_artifacts::try_record_tool_run_complete_settled(
                record,
                &output,
                observation,
                dispatched.completion,
            )?;
            Ok(output)
        }
        Err(error) => match crate::run_artifacts::try_record_tool_run_failed_settled(
            record,
            &error.to_string(),
            observation,
            dispatched.completion,
        ) {
            Ok(()) => Err(error),
            Err(persistence) => Err(anyhow::anyhow!(
                "{error:#}; additionally, child run persistence failed: {persistence:#}"
            )),
        },
    }
}

fn validate_sast_scan_engine_result(name: &str, output: &Value) -> Result<()> {
    if crate::tool_result_status(output) != crate::ToolResultStatus::Failed {
        return Ok(());
    }
    validate_sast_subtool_result(name, output)
}

fn scan_engine_outcome(output: &Value) -> crate::run_artifacts::ScanEngineStageOutcome {
    use crate::run_artifacts::ScanEngineStageOutcome;
    match crate::tool_result_status(output) {
        crate::ToolResultStatus::Completed => ScanEngineStageOutcome::Complete,
        crate::ToolResultStatus::Partial => ScanEngineStageOutcome::Partial,
        crate::ToolResultStatus::Skipped => ScanEngineStageOutcome::Skipped,
        crate::ToolResultStatus::Failed => ScanEngineStageOutcome::Failed,
    }
}

/// The scan's `paths` scope becomes agentic SAST's include patterns (each
/// path and everything below it). The shared scope guard rejects conflicting
/// explicit patterns before this adapter runs.
fn agentic_scoped_input(input: &Value) -> Value {
    let mut scoped = super::agentic_settings::bind_turn_limit(input);
    let explicit = ["includePatterns", "include_patterns"].iter().any(|key| {
        input
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
    });
    let paths = scan_scope_paths(input);
    if let (false, Some(object), false) = (explicit, scoped.as_object_mut(), paths.is_empty()) {
        object.insert("includePatterns".to_string(), json!(scope_patterns(&paths)));
    }
    scoped
}

fn scan_scope_paths(input: &Value) -> Vec<String> {
    ["paths", "includePaths", "include_paths"]
        .iter()
        .find_map(|key| input.get(key).and_then(Value::as_array))
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|path| path.trim().trim_end_matches('/').to_string())
                .filter(|path| !path.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn single_scope_directory(input: &Value, root: Option<&std::path::Path>) -> Option<String> {
    let explicit = ["targetSubdir", "target_subdir"]
        .iter()
        .any(|key| input.get(key).is_some());
    let [path] = scan_scope_paths(input).try_into().ok()?;
    (!explicit && root?.join(&path).is_dir()).then_some(path)
}

fn scope_patterns(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .flat_map(|path| [path.clone(), format!("{path}/*")])
        .collect()
}

fn descriptor_filtered_input(
    registry: &ModuleRegistry,
    tool_name: &str,
    input: &Value,
) -> Result<Value> {
    let Some(object) = input.as_object() else {
        return Ok(input.clone());
    };
    let descriptor = registry
        .resolve_tool(tool_name)
        .with_context(|| format!("sast:scan subtool {tool_name:?} is not registered"))?;
    let filtered = object
        .iter()
        .filter(|(key, _)| {
            descriptor
                .options
                .iter()
                .any(|option| option.matches_name_or_alias(key))
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    Ok(Value::Object(filtered))
}

fn taint_iris_next_report_from_tool_output(output: &Value) -> Result<TaintIrisNextReport> {
    let data = output
        .get("data")
        .cloned()
        .context("taint-iris-next:hunt output did not include data")?;
    let findings = taint_iris_next_findings(&data, "findings")?;
    let review_candidates = taint_iris_next_findings(&data, "reviewCandidates")?;
    let persisted = serde_json::from_value(data.get("persisted").cloned().unwrap_or(Value::Null))
        .context("taint-iris-next:hunt data.persisted was invalid")?;
    let selected_cwes = selected_cwes_from_taint_iris_next_data(&data);
    let count = taint_iris_next_count(&data, &findings, &review_candidates);
    let exact_cost = output.get("costUsd").and_then(Value::as_f64);
    let observed_cost = output
        .get("observedCostUsd")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let cost_usd = exact_cost.unwrap_or(observed_cost);
    crate::runtime::RuntimeCost::from_usd(cost_usd, "taint-iris-next subtool cost")?;
    Ok(TaintIrisNextReport {
        target: taint_iris_next_string(&data, "target", ""),
        status: taint_iris_next_string(&data, "status", ""),
        mode: taint_iris_next_string(&data, "mode", "hunt"),
        count,
        findings,
        review_candidates,
        selected_cwes,
        persisted,
        cost_usd,
        cost_usd_exact: exact_cost.is_some(),
        ok: output.get("ok").and_then(Value::as_bool).unwrap_or(true),
        output: taint_iris_next_string(output, "output", ""),
        data,
    })
}

fn taint_iris_next_findings(data: &Value, key: &str) -> Result<Vec<Finding>> {
    serde_json::from_value(data.get(key).cloned().unwrap_or_else(|| json!([])))
        .with_context(|| format!("taint-iris-next:hunt data.{key} was invalid"))
}

fn selected_cwes_from_taint_iris_next_data(data: &Value) -> Vec<Value> {
    data.get("selectedCwes")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn taint_iris_next_count(
    data: &Value,
    findings: &[Finding],
    review_candidates: &[Finding],
) -> usize {
    json_pointer_usize(data, "/stats/totalFindings")
        .unwrap_or_else(|| findings_count_excluding_review_candidates(findings, review_candidates))
}

fn taint_iris_next_string(data: &Value, key: &str, default: &str) -> String {
    data.get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn json_pointer_usize(value: &Value, pointer: &str) -> Option<usize> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
}

fn findings_count_excluding_review_candidates(
    findings: &[crate::findings::Finding],
    review_candidates: &[crate::findings::Finding],
) -> usize {
    findings.len().saturating_sub(review_candidates.len())
}

#[cfg(test)]
mod canonical_report_cost_tests {
    use super::*;

    #[test]
    fn scan_paths_scope_the_agentic_inventory_after_shared_guard_validation() {
        let scoped = agentic_scoped_input(&json!({"paths": ["routes/", "lib/insecurity.ts"]}));
        assert_eq!(
            scoped["includePatterns"],
            json!([
                "routes",
                "routes/*",
                "lib/insecurity.ts",
                "lib/insecurity.ts/*"
            ])
        );
        assert!(crate::capabilities::agentic_sast::agentic_path_allowed(
            "routes/login.ts",
            &serde_json::from_value::<Vec<String>>(scoped["includePatterns"].clone()).unwrap(),
            &[],
        ));

        let empty_patterns =
            agentic_scoped_input(&json!({"paths":["routes"], "includePatterns":[]}));
        assert_eq!(
            empty_patterns["includePatterns"],
            json!(["routes", "routes/*"])
        );
        let explicit = json!({"includePatterns": ["lib/*"]});
        assert_eq!(agentic_scoped_input(&explicit), explicit);
        let unscoped = json!({"mode": "standard"});
        assert_eq!(agentic_scoped_input(&unscoped), unscoped);
    }

    #[test]
    fn only_a_single_existing_directory_scopes_taint_iris_next() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("routes")).unwrap();
        std::fs::write(root.path().join("server.ts"), "").unwrap();
        let single =
            |paths: Value| single_scope_directory(&json!({ "paths": paths }), Some(root.path()));

        assert_eq!(single(json!(["routes/"])).as_deref(), Some("routes"));
        assert_eq!(
            single(json!(["server.ts"])),
            None,
            "a file is not a subdirectory"
        );
        assert_eq!(
            single(json!(["routes", "lib"])),
            None,
            "unsupported multiple scopes are rejected by the shared guard"
        );
        let explicit = json!({"paths": ["routes"], "targetSubdir": "lib"});
        assert_eq!(single_scope_directory(&explicit, Some(root.path())), None);
    }

    #[test]
    fn normalized_incomplete_subtool_reports_rehydrate_observed_cost() {
        let agentic: AgenticSastReport = serde_json::from_value(json!({
            "target": "/repo",
            "count": 0,
            "findings": [],
            "observedCostUsd": 0.125,
            "costUsdExact": false
        }))
        .unwrap();
        let carlini: CarliniThreatHuntReport = serde_json::from_value(json!({
            "target": "/repo",
            "count": 0,
            "actors": 1,
            "actorRuns": 1,
            "promptInventoryFiles": 0,
            "threatFocusedPromptFiles": 0,
            "findings": [],
            "observedCostUsd": 0.125,
            "costUsdExact": false
        }))
        .unwrap();
        let systems: SystemsHuntReport = serde_json::from_value(json!({
            "target": "/repo",
            "count": 0,
            "findings": [],
            "artifacts": [],
            "observedCostUsd": 0.125,
            "costUsdExact": false
        }))
        .unwrap();

        for (observed, exact) in [
            (agentic.cost_usd, agentic.cost_usd_exact),
            (carlini.cost_usd, carlini.cost_usd_exact),
            (systems.cost_usd, systems.cost_usd_exact),
        ] {
            assert_eq!(observed, 0.125);
            assert!(!exact);
        }
    }

    #[test]
    fn legacy_exact_subtool_report_defaults_cost_exactness_to_true() {
        let report: AgenticSastReport = serde_json::from_value(json!({
            "target": "/repo",
            "count": 0,
            "findings": [],
            "costUsd": 0.25
        }))
        .unwrap();

        assert_eq!(report.cost_usd, 0.25);
        assert!(report.cost_usd_exact);
        assert!(serde_json::to_value(report)
            .unwrap()
            .get("costUsdExact")
            .is_none());
    }

    #[test]
    fn usable_partial_scan_engine_retains_its_partial_status() {
        let output = json!({"ok": true, "status": "partial", "data": {}});

        validate_sast_scan_engine_result("agentic-sast:scan", &output).unwrap();

        assert_eq!(
            scan_engine_outcome(&output),
            crate::run_artifacts::ScanEngineStageOutcome::Partial
        );
    }

    #[test]
    fn failed_scan_engine_aborts_the_composite_report() {
        let output = json!({
            "ok": false,
            "status": "failed",
            "errors": ["runtime disconnected"]
        });

        let error = validate_sast_scan_engine_result("agentic-sast:scan", &output).unwrap_err();

        assert!(error.to_string().contains("runtime disconnected"));
    }
}

#[cfg(test)]
mod catalog_pin_forwarding_tests {
    use super::*;
    #[test]
    fn umbrella_option_preparation_and_real_child_filter_keep_the_exact_catalog_pin() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        let pin = "a".repeat(64);
        let parent = registry
            .prepare_tool_input("sast:scan", json!({"catalog_digest_ref":pin}), None)
            .unwrap();
        let input = taint_iris_next_hunt_input(&parent);
        let child = descriptor_filtered_input(&registry, "taint-iris-next:hunt", &input).unwrap();
        let prepared = registry
            .prepare_tool_input("taint-iris-next:hunt", child, None)
            .unwrap();
        assert_eq!(prepared["catalogDigestRef"], pin);
        assert_eq!(prepared["mode"], "hunt");
        assert!(prepared.get("tasks").is_none());
    }
}
