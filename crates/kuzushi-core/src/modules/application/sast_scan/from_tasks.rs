use super::*;

impl SastTaskSelection {
    pub(in crate::modules) fn from_tasks(tasks: Vec<String>) -> Result<Self> {
        let (
            native_tasks,
            run_agentic,
            run_carlini,
            run_taint_iris,
            run_taint_iris_next,
            run_systems_hunt,
        ) = split_agentic_sast_tasks(tasks);
        let scanners = selected_native_scanners(
            &native_tasks,
            run_agentic || run_carlini || run_taint_iris || run_taint_iris_next || run_systems_hunt,
        )?;
        let engine_ids = scanners
            .iter()
            .map(|scanner| scanner.id())
            .collect::<Vec<_>>();
        Ok(Self {
            scanners,
            run_agentic,
            run_carlini,
            run_taint_iris,
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
        self.run_agentic
            || self.run_carlini
            || self.run_taint_iris
            || self.run_taint_iris_next
            || self.run_systems_hunt
    }

    pub(in crate::modules) fn run_native(
        &self,
        workspace: &crate::workspace::WorkspaceTarget,
        store: &crate::findings::FindingStore,
        options: &ScanRunOptions,
    ) -> Result<Option<ScanRun>> {
        if self.scanners.is_empty() {
            Ok(None)
        } else {
            Ok(Some(run_scan_engines_with_options(
                workspace,
                store,
                &self.scanners,
                options,
            )?))
        }
    }
}

pub(in crate::modules) fn selected_native_scanners(
    native_tasks: &[String],
    only_agentic_tasks: bool,
) -> Result<Vec<Box<dyn ScanEngine>>> {
    if native_tasks.is_empty() && only_agentic_tasks {
        Ok(Vec::new())
    } else {
        scan_engines_for_tasks(native_tasks)
    }
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
    fill_taint_iris_report(reports, selected, &dispatch)?;
    fill_taint_iris_next_report(reports, selected, &dispatch)?;
    fill_systems_hunt_report(reports, selected, &dispatch)
}

fn fill_agentic_sast_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_agentic {
        reports.engine_ids.push("agentic");
        reports.agentic = Some(dispatch.report_from_data("agentic-sast:scan")?);
    }
    Ok(())
}

fn fill_offense_review_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_carlini {
        reports.engine_ids.push("offense-review");
        reports.carlini = Some(dispatch.report_from_data("offense-review:threat-hunt")?);
    }
    Ok(())
}

fn fill_taint_iris_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_taint_iris {
        reports.engine_ids.push("taint-iris");
        reports.taint_iris = Some(dispatch.report_from_data("taint-iris:hunt")?);
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
        reports.taint_iris_next = Some(dispatch.taint_iris_next_report()?);
    }
    Ok(())
}

fn fill_systems_hunt_report(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    dispatch: &SastSubtoolDispatch<'_>,
) -> Result<()> {
    if selected.run_systems_hunt {
        reports.engine_ids.push("systems-hunt");
        reports.systems_hunt = Some(dispatch.report_from_data("systems-hunt:systems-hunt")?);
    }
    Ok(())
}

struct SastSubtoolDispatch<'a> {
    registry: &'a ModuleRegistry,
    option_store: &'a crate::options::ToolOptionStore,
    input: &'a Value,
    ctx: &'a ToolExecutionContext<'a>,
    runtime: Option<&'a dyn AgentRuntime>,
}

impl SastSubtoolDispatch<'_> {
    fn report_from_data<T>(&self, tool_name: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let output = self.run(tool_name, self.input)?;
        let data = output
            .get("data")
            .cloned()
            .with_context(|| format!("{tool_name} output did not include data"))?;
        serde_json::from_value(data)
            .with_context(|| format!("{tool_name} returned invalid report data"))
    }

    fn taint_iris_next_report(&self) -> Result<TaintIrisNextReport> {
        let tool_name = "taint-iris-next:hunt";
        let output = self.run(tool_name, &taint_iris_next_hunt_input(self.input))?;
        taint_iris_next_report_from_tool_output(&output)
    }

    fn run(&self, tool_name: &str, input: &Value) -> Result<Value> {
        let input = descriptor_filtered_input(self.registry, tool_name, input)?;
        run_sast_subtool(
            self.registry,
            tool_name,
            input,
            self.ctx,
            self.runtime,
            self.option_store,
        )
    }
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
    Ok(TaintIrisNextReport {
        target: taint_iris_next_string(&data, "target", ""),
        status: taint_iris_next_string(&data, "status", ""),
        mode: taint_iris_next_string(&data, "mode", "hunt"),
        count,
        findings,
        review_candidates,
        selected_cwes,
        persisted,
        cost_usd: output.get("costUsd").and_then(Value::as_f64).unwrap_or(0.0),
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
