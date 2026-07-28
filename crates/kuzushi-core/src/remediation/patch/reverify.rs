mod support;

use self::support::*;
use crate::capabilities::patch_reverification::{
    prepare_empirical_ladder, EmpiricalLadderRun, ProductionEmpiricalCaseRunner,
};
use crate::findings::{PatchLifecycleRecord, PatchLifecycleState};
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::runtime::AgentRuntime;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(crate) fn bind_patch_reverify_input(
    mut input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let application_id = required_string(&input, APPLICATION_ID)?;
    let workspace = ctx
        .workspace
        .context("patch:reverify requires an explicit active workspace")?;
    let opened_store;
    let store = match ctx.findings_store {
        Some(store) => store,
        None => {
            opened_store = crate::findings::FindingStore::open(workspace.findings_db_path())?;
            &opened_store
        }
    };
    let record = load_record(store, application_id, workspace.root())?;
    let object = input
        .as_object_mut()
        .context("patch:reverify input must be a JSON object")?;
    bind_originating_detector(object, store, workspace.root(), &record);
    Ok(input)
}

pub(crate) fn run_patch_reverify(
    registry: &ModuleRegistry,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let mut request = ReverifyRequest::load(&input, ctx)?;
    if let Some(output) = request.preflight(&input)? {
        return Ok(output);
    }
    let detector = BoundDetector::load(&input)?;
    request.mark_running(&detector.tool)?;
    continue_reverification(registry, request, detector, ctx, runtime)
}

fn continue_reverification(
    registry: &ModuleRegistry,
    request: ReverifyRequest<'_>,
    detector: BoundDetector,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let empirical: Option<EmpiricalLadderRun> = match prepare_empirical_ladder(
        request.store,
        request.target,
        &request.record,
        &detector.tool,
        &detector.run_id,
        &ProductionEmpiricalCaseRunner,
    ) {
        Ok(empirical) => empirical,
        Err(error) => return finish_empirical_error(request, &detector.tool, error),
    };
    if let Some(run) = terminal_empirical_run(&empirical) {
        return finish_terminal_empirical(request, &detector.tool, run);
    }
    execute_detector(
        registry,
        request,
        &detector.tool,
        detector.input,
        empirical.map(|run| run.receipt),
        ctx,
        runtime,
    )
}

fn finish_empirical_error(
    mut request: ReverifyRequest<'_>,
    detector: &str,
    error: anyhow::Error,
) -> Result<Value> {
    let mut state = PatchLifecycleState::Inconclusive;
    let mut detail = format!("empirical patch reverification was inconclusive: {error}");
    if let Some(path) = changed_touched_path(request.target, &request.record)? {
        state = PatchLifecycleState::ChangedSinceApply;
        detail = format!("{path} changed during empirical reverification");
    }
    record_state(request.store, &mut request.record, state, Some(detail))?;
    Ok(completed_reverify_output(&request.record, detector))
}

fn terminal_empirical_run(empirical: &Option<EmpiricalLadderRun>) -> Option<&EmpiricalLadderRun> {
    empirical
        .as_ref()
        .filter(|run| run.terminal_state.is_some())
}

fn finish_terminal_empirical(
    request: ReverifyRequest<'_>,
    detector: &str,
    run: &EmpiricalLadderRun,
) -> Result<Value> {
    let state = run.terminal_state.expect("filtered terminal empirical run");
    finish_with_receipt(
        request,
        state,
        empirical_outcome_detail(state),
        run.receipt.clone(),
        detector,
    )
}

struct BoundDetector {
    tool: String,
    run_id: String,
    input: Value,
}

impl BoundDetector {
    fn load(input: &Value) -> Result<Self> {
        Ok(Self {
            tool: required_string(input, DETECTOR_TOOL)?.to_string(),
            run_id: required_string(input, DETECTOR_RUN_ID)?.to_string(),
            input: input
                .get(DETECTOR_INPUT)
                .cloned()
                .context("patch:reverify is missing its bound detector input")?,
        })
    }
}

struct ReverifyRequest<'a> {
    store: &'a crate::findings::FindingStore,
    target: &'a Path,
    record: PatchLifecycleRecord,
}

impl<'a> ReverifyRequest<'a> {
    fn load(input: &Value, ctx: &'a ToolExecutionContext<'_>) -> Result<Self> {
        let application_id = required_string(input, APPLICATION_ID)?;
        let workspace = ctx
            .workspace
            .context("patch:reverify requires an explicit active workspace")?;
        let store = ctx
            .findings_store
            .context("patch:reverify requires the active workspace findings store")?;
        let mut record = load_record(store, application_id, workspace.root())?;
        record.reverify_run_id = ctx.run_id();
        Ok(Self {
            store,
            target: workspace.root(),
            record,
        })
    }

    fn preflight(&mut self, input: &Value) -> Result<Option<Value>> {
        let Some(path) = changed_touched_path(self.target, &self.record)? else {
            if let Some(reason) = input.get(COMPARISON_UNAVAILABLE).and_then(Value::as_str) {
                return self.finish_preflight(PatchLifecycleState::Inconclusive, reason, false);
            }
            return Ok(None);
        };
        let detail = format!("{path} changed after the patch application");
        self.finish_preflight(PatchLifecycleState::ChangedSinceApply, &detail, true)
    }

    fn finish_preflight(
        &mut self,
        state: PatchLifecycleState,
        detail: &str,
        failed: bool,
    ) -> Result<Option<Value>> {
        record_state(
            self.store,
            &mut self.record,
            state,
            Some(detail.to_string()),
        )?;
        let output = if failed {
            failed_reverify_output(&self.record, detail)
        } else {
            completed_reverify_output(&self.record, "unavailable")
        };
        Ok(Some(output))
    }

    fn mark_running(&mut self, detector: &str) -> Result<()> {
        record_state(
            self.store,
            &mut self.record,
            PatchLifecycleState::ReverifyRunning,
            Some(format!("replaying {detector}")),
        )
    }

    fn cloned(&self) -> Self {
        Self {
            store: self.store,
            target: self.target,
            record: self.record.clone(),
        }
    }
}

fn execute_detector(
    registry: &ModuleRegistry,
    mut request: ReverifyRequest<'_>,
    detector: &str,
    detector_input: Value,
    receipt: Option<crate::findings::PatchReverificationReceipt>,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let output =
        match registry.dispatch_delegated_tool_with_runtime(detector, detector_input, ctx, runtime)
        {
            Ok(output) => output,
            Err(error) => return record_dispatch_error(&mut request, receipt, ctx, error),
        };
    finish_detector_output(request, detector, output, receipt, ctx)
}

#[cfg(test)]
mod legacy_provenance_tests {
    use super::*;
    use crate::findings::{Finding, PatchResult, PatchStatus, Severity};
    use serde_json::json;

    #[test]
    fn legacy_missing_provenance_persists_inconclusive_with_regeneration_next_step() {
        let (target, store, record) = legacy_reverify_fixture();
        let mut input = json!({APPLICATION_ID: record.application_id});
        bind_originating_detector(
            input.as_object_mut().unwrap(),
            &store,
            target.path(),
            &record,
        );
        let reason = input[COMPARISON_UNAVAILABLE].as_str().unwrap();
        assert!(reason.contains("regenerate"), "{reason}");
        let mut request = ReverifyRequest {
            store: &store,
            target: target.path(),
            record: record.clone(),
        };

        assert!(request.preflight(&input).unwrap().is_some());
        let persisted = store
            .get_patch_lifecycle(&record.application_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.state, PatchLifecycleState::Inconclusive);
        assert!(persisted
            .detail
            .is_some_and(|detail| detail.contains("regenerate")));
    }

    fn legacy_reverify_fixture() -> (
        tempfile::TempDir,
        crate::findings::FindingStore,
        PatchLifecycleRecord,
    ) {
        let target = tempfile::tempdir().unwrap();
        let store =
            crate::findings::FindingStore::open(target.path().join(".kuzushi/v3/index.sqlite3"))
                .unwrap();
        store
            .record_run_started("scan-1", target.path(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "rule.one",
            "src/app.rs",
            3,
            Some(3),
            Severity::High,
            "finding",
        );
        store.insert_finding("scan-1", &finding).unwrap();
        store.insert_patch_result(&legacy_patch(&finding)).unwrap();
        let record = applied_record(&store, target.path(), &finding);
        store.insert_patch_lifecycle_record(&record).unwrap();
        (target, store, record)
    }

    fn legacy_patch(finding: &Finding) -> PatchResult {
        PatchResult {
            patch_run_id: "patch-run-1".to_string(),
            fingerprint: finding.fingerprint.clone(),
            repo: "/target".to_string(),
            diff: Some("diff --git a/src/app.rs b/src/app.rs\n".to_string()),
            status: PatchStatus::Sound,
            iterations: 1,
            build_command: None,
            test_command: None,
            worktree_path: None,
            cost_usd: Some(0.0),
            provider_spend_unresolved: false,
            validator_log: None,
            history: Vec::new(),
            provenance: None,
            created_at: None,
            updated_at: None,
        }
    }

    fn applied_record(
        store: &crate::findings::FindingStore,
        target: &Path,
        finding: &Finding,
    ) -> PatchLifecycleRecord {
        PatchLifecycleRecord {
            application_id: "application-legacy".to_string(),
            stable_fp: store
                .patch_lifecycle_stable_fp(&finding.fingerprint)
                .unwrap(),
            fingerprint: finding.fingerprint.clone(),
            finding_scan_id: finding
                .scan_id
                .clone()
                .or_else(|| Some("scan-1".to_string())),
            patch_run_id: "patch-run-1".to_string(),
            target: target.display().to_string(),
            diff_hash: "diff-hash".to_string(),
            base_commit: Some("source-commit".to_string()),
            touched_files: Vec::new(),
            state: PatchLifecycleState::Applied,
            reverify_run_id: None,
            reverify_evidence: None,
            detail: None,
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("1".to_string()),
            updated_at: "1".to_string(),
        }
    }
}
