use super::worker_resolution::BatchWorkerResolution;
use super::{resolve_batch_workers, BatchScanConfig};
use crate::app::{force_shell_discovery_only_sast_input, ShellApp};
use anyhow::{Context, Result};
use kuzushi_core::capabilities::campaign::{
    compile_scan_batch_plan, CampaignPlanHandle, ScanBatchGatePolicy, ScanBatchPlanSpec,
};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::WorkspaceTarget;
use std::path::Path;

pub(super) struct PreparedBatchLaunch {
    pub(super) plan: CampaignPlanHandle,
    pub(super) effective_workers: usize,
    pub(super) clamp_reason: Option<String>,
}

pub(super) fn prepare_batch_launch(
    app: &ShellApp,
    target: &Path,
    config: &BatchScanConfig,
) -> Result<PreparedBatchLaunch> {
    let workspace = initialized_workspace(target)?;
    let prepared_input = prepared_scan_input(app, &workspace)?;
    let workers = resolve_batch_workers(
        app.registry(),
        &prepared_input,
        config.requested_workers,
        config.trials,
    )?;
    let plan = compile_scan_batch_plan(ScanBatchPlanSpec {
        root: workspace.root(),
        batch_id: None,
        trials: config.trials,
        requested_workers: config.requested_workers,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input,
        config: app.config(),
        registry: app.registry(),
    })?;
    let effective_workers = plan.effective_workers;
    let clamp_reason = plan.parallel_safety.clamp_reason.clone().or(workers.reason);
    Ok(PreparedBatchLaunch {
        plan,
        effective_workers,
        clamp_reason,
    })
}

pub(super) fn resolve_config_workers(
    app: &ShellApp,
    target: &Path,
    config: &BatchScanConfig,
) -> Result<BatchWorkerResolution> {
    let workspace = initialized_workspace(target)?;
    let prepared_input = prepared_scan_input(app, &workspace)?;
    resolve_batch_workers(
        app.registry(),
        &prepared_input,
        config.requested_workers,
        config.trials,
    )
}

fn initialized_workspace(target: &Path) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(target)
        .with_context(|| format!("could not open batch target {}", target.display()))?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

fn prepared_scan_input(app: &ShellApp, workspace: &WorkspaceTarget) -> Result<serde_json::Value> {
    let input = force_shell_discovery_only_sast_input("sast:scan", serde_json::json!({}));
    let context = ToolExecutionContext {
        config: app.config(),
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = app.registry().prepare_dispatch_input(
        "sast:scan",
        input,
        &context,
        Some(app.option_store()),
    )?;
    Ok(prepared.value().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{OptionScope, OptionTarget, V2Config};

    #[test]
    fn launch_preparation_uses_canonical_stored_scan_input() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("source.rs"), "fn main() {}\n").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        app.option_store_mut().set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "identityFold",
            serde_json::json!("safe"),
        );
        let config = BatchScanConfig::load(target.path(), None);

        let launch = prepare_batch_launch(&app, target.path(), &config).unwrap();
        let plan: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&launch.plan.plan_path).unwrap()).unwrap();

        assert_eq!(plan["kind"], "scan-batch");
        assert_eq!(plan["baseInput"]["identityFold"], "safe");
        assert_eq!(plan["baseInput"]["triage"], false);
    }
}
