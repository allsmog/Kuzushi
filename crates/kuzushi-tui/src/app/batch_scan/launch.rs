use super::worker_resolution::BatchWorkerResolution;
use super::{resolve_batch_workers, BatchScanConfig};
use crate::app::{force_shell_discovery_only_sast_input, ShellApp};
use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::WorkspaceTarget;
use std::path::Path;

/// Prepare stored options through the same canonical boundary as a direct scan.
/// Snapshot hashing and immutable plan compilation run in the normal tool worker.
pub(super) fn study_input(
    app: &ShellApp,
    target: &Path,
    config: &BatchScanConfig,
    campaign_id: &str,
) -> Result<serde_json::Value> {
    let workspace = initialized_workspace(target)?;
    let input = configured_scan_input(app, &workspace, config)?;
    Ok(serde_json::json!({
        "campaignId": campaign_id,
        "investigationId": config.study.investigation_id,
        "trials": config.trials,
        "workers": config.requested_workers,
        "scanInput": input,
    }))
}

pub(super) fn resolve_config_workers(
    app: &ShellApp,
    target: &Path,
    config: &BatchScanConfig,
) -> Result<BatchWorkerResolution> {
    let workspace = initialized_workspace(target)?;
    let prepared_input = configured_scan_input(app, &workspace, config)?;
    resolve_batch_workers(
        app.registry(),
        &prepared_input,
        config.requested_workers,
        config.trials,
    )
}

pub(super) fn configured_scan_input(
    app: &ShellApp,
    workspace: &WorkspaceTarget,
    config: &BatchScanConfig,
) -> Result<serde_json::Value> {
    match &config.study.scan_input {
        Some(input) => Ok(input.clone()),
        None => prepared_scan_input(app, workspace),
    }
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

        let plan = study_input(&app, target.path(), &config, "study").unwrap();
        assert_eq!(plan["trials"], 3);
        assert_eq!(plan["scanInput"]["identityFold"], "safe");
        assert_eq!(plan["scanInput"]["triage"], false);
        assert!(!target
            .path()
            .join(".kuzushi/v3/campaigns/study/plan.json")
            .exists());
    }
}
