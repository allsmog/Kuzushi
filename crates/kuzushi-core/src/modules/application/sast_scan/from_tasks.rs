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
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<()> {
    if selected.run_agentic {
        reports.engine_ids.push("agentic");
        reports.agentic = Some(run_agentic_sast_report(input, ctx, runtime)?);
    }
    if selected.run_carlini {
        reports.engine_ids.push("carlini-threat-hunt");
        reports.carlini = Some(run_carlini_threat_hunt_report(input, ctx, runtime)?);
    }
    if selected.run_taint_iris {
        reports.engine_ids.push("taint-iris");
        reports.taint_iris = Some(run_taint_iris_report(input, ctx, runtime)?);
    }
    if selected.run_taint_iris_next {
        reports.engine_ids.push("taint-iris-next");
        reports.taint_iris_next = Some(run_taint_iris_next_report(
            &taint_iris_next_hunt_input(input),
            ctx,
            runtime,
        )?);
    }
    if selected.run_systems_hunt {
        reports.engine_ids.push("systems-hunt");
        reports.systems_hunt = Some(run_systems_hunt_report(input, ctx, runtime)?);
    }
    Ok(())
}
