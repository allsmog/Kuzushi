//! Publish direct scanner evidence only after source authentication settles.
use super::*;
use crate::run_artifacts::*;
use crate::run_lifecycle::RunItemStatus;
use crate::workflow_attempts::PhaseTargetSnapshot;
use std::time::Instant;

mod build;

pub(super) enum DirectScanPolicy {
    Iac(crate::iac_scan::IacScanKind),
    CargoAudit,
}

pub(super) struct DirectScanReceipt {
    policy: DirectScanPolicy,
    scope: ScanStageScope,
    snapshot: PhaseTargetSnapshot,
    started: Instant,
}

impl DirectScanReceipt {
    pub(super) fn capture(
        ctx: &ToolExecutionContext<'_>,
        target: &Path,
        policy: DirectScanPolicy,
    ) -> Result<Self> {
        let root = ctx.workspace.map_or(target, |workspace| workspace.root());
        let relative = target
            .strip_prefix(root)
            .context("Scan target is outside its workspace")?;
        let path = match policy {
            DirectScanPolicy::Iac(_) => relative.to_path_buf(),
            DirectScanPolicy::CargoAudit => relative.join("Cargo.lock"),
        };
        Ok(Self {
            policy,
            scope: ScanStageScope {
                target: root.display().to_string(),
                paths: vec![if path.as_os_str().is_empty() {
                    ".".into()
                } else {
                    crate::workspace::inventory::repo_relative(Path::new(""), &path)
                }],
                inspected_files: None,
            },
            snapshot: PhaseTargetSnapshot::capture(root),
            started: Instant::now(),
        })
    }

    pub(super) fn finish(
        self,
        ctx: &ToolExecutionContext<'_>,
        findings: &[Finding],
        mut output: Value,
    ) -> Result<Value> {
        let Some(status) = scan_persistence_status(crate::tool_result_status(&output)) else {
            return Ok(output);
        };
        let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
            return Ok(output);
        };
        workspace.ensure_state_dir()?;
        let run = ctx.finding_run_id();
        let (added, updated) = crate::findings::commit_observed_findings_with_counts(
            store,
            ctx.run_observation().as_ref(),
            &run,
            workspace.root(),
            findings,
            status,
        )?;
        let engine = self.policy.engine();
        let stage = self.publish(
            workspace,
            store,
            &run,
            status,
            ScanFindingDelta { added, updated },
            &output,
        )?;
        output["data"]["persisted"] =
            json!({"runId":run,"findingsDb":workspace.findings_db_path().display().to_string()});
        output["data"]["phaseStages"] = json!([stage]);
        super::register_modules::emit_scan_done(ctx, engine, findings.len());
        Ok(output)
    }

    fn publish(
        self,
        workspace: &crate::WorkspaceTarget,
        store: &crate::FindingStore,
        run: &str,
        status: RunItemStatus,
        delta: ScanFindingDelta,
        output: &Value,
    ) -> Result<PhaseStageReceipt> {
        let findings = store.list_findings_for_scan_id(run)?;
        write_run_artifact_json(
            workspace.root(),
            run,
            "findings.json",
            "discovery observations",
            &json!(findings),
        )?;
        let stage = self.build(run, status, delta, &findings, output)?;
        append_run_artifact_jsonl_value(
            workspace.root(),
            run,
            SAST_PHASE_STAGES_JSONL_FILE,
            &json!(stage),
        )?;
        let scan = stage
            .scan
            .as_ref()
            .context("Direct scan coverage is unavailable")?;
        store.reconcile_completed_scan_coverage(run, stage.outcome, scan)?;
        Ok(stage)
    }
}
