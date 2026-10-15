use super::worker_resolution::BatchWorkerResolution;
use super::{resolve_batch_workers, BatchScanConfig};
use crate::app::{force_shell_discovery_only_sast_input, ShellApp};
use anyhow::{Context, Result};
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
    config.study.ensure_accounting_ready()?;
    initialized_workspace(target)?;
    let input = configured_scan_input(app, config)?;
    let mut input = serde_json::json!({
        "campaignId": campaign_id,
        "investigationId": config.study.investigation_id,
        "trials": config.trials,
        "workers": config.requested_workers,
        "scanInput": input,
    });
    if let Some(run) = &config.prior_run_id {
        input["baselineRunId"] = serde_json::json!(run);
    }
    bind_brief_input(&mut input, config);
    if let Some(campaign) = &config.prior_campaign_id {
        input["resourceBaselineCampaignId"] = serde_json::json!(campaign);
    }
    if let Some(run) = &config.study.context_baseline_run_id {
        input["contextBaselineRunId"] = serde_json::json!(run);
    }
    bind_matrix_input(&mut input, config);
    super::scope_study::bind_scope_input(&mut input, config);
    Ok(input)
}

pub(super) fn bind_brief_input(input: &mut serde_json::Value, config: &BatchScanConfig) {
    if let Some(brief) = &config.study.brief {
        input["briefRef"] = serde_json::json!(brief.reference);
    }
}

fn bind_matrix_input(input: &mut serde_json::Value, config: &BatchScanConfig) {
    if !config.study.matrix.cases.is_empty() {
        input["contextCases"] = serde_json::json!(config.study.matrix.cases);
        input["baselineCaseId"] = serde_json::json!(config.study.matrix.baseline_case_id);
        if let Some(object) = input["scanInput"].as_object_mut() {
            object.remove("threatModelRef");
            object.remove("threat_model_ref");
        }
    }
}

pub(super) fn resolve_config_workers(
    app: &ShellApp,
    target: &Path,
    config: &BatchScanConfig,
) -> Result<BatchWorkerResolution> {
    initialized_workspace(target)?;
    let prepared_input =
        super::scope_study::picker_input(config, configured_scan_input(app, config)?);
    resolve_batch_workers(
        app.registry(),
        &prepared_input,
        config.requested_workers,
        super::scope_study::job_count(config),
    )
}

pub(super) fn configured_scan_input(
    app: &ShellApp,
    config: &BatchScanConfig,
) -> Result<serde_json::Value> {
    match &config.study.scan_input {
        Some(input) => Ok(input.clone()),
        None => preview_scan_input(app),
    }
}

fn initialized_workspace(target: &Path) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(target)
        .with_context(|| format!("could not open batch target {}", target.display()))?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

pub(super) fn preview_scan_input(app: &ShellApp) -> Result<serde_json::Value> {
    let mut input = force_shell_discovery_only_sast_input("sast:scan", serde_json::json!({}));
    let stored = app.option_store().effective_stored_values("sast:scan");
    if !stored.contains_key("threatModelRef") && !stored.contains_key("threat_model_ref") {
        bind_presented_map_context(app, &mut input)?;
        bind_presented_catalog_context(app, &mut input)?;
    }
    // This is an options preview. Admission, source hashing and prompt binding
    // run through prepared dispatch in the campaign worker before publication.
    app.registry()
        .prepare_tool_input("sast:scan", input, Some(app.option_store()))
}

fn bind_presented_catalog_context(app: &ShellApp, input: &mut serde_json::Value) -> Result<()> {
    if input.get("threatModelRef").is_some() {
        return Ok(());
    }
    let cached = app
        .workbench_cache()
        .borrow()
        .cached_threat_model_store(app.target());
    if let crate::app::ViewDataState::Ready(crate::app::ThreatModelStoreState::Ready {
        manifest,
        ..
    }) = cached
    {
        input["threatModelRef"] = serde_json::to_value(manifest.active)?;
    }
    Ok(())
}

pub(super) fn bind_presented_map_context(
    app: &ShellApp,
    input: &mut serde_json::Value,
) -> Result<()> {
    if input.get("threatModelRef").is_some() {
        return Ok(());
    }
    let Some(attempt) = app
        .engagement
        .selected_phase_attempt(kuzushi_core::WorkflowPhase::Map)
    else {
        anyhow::ensure!(
            app.engagement.stale_selected_phase_attempt(kuzushi_core::WorkflowPhase::Map).is_none(),
            "Accepted Map belongs to earlier source content. Accept a current Map or explicitly select study context."
        );
        return Ok(());
    };
    let cached = app.workbench_cache().borrow().cached_map_run_context(
        app.target()
            .context("Accepted Map requires a selected target")?,
        &attempt.completed.run_refs,
    );
    let crate::app::ViewDataState::Ready(context) = cached else {
        anyhow::bail!("Accepted Map context is loading. Try again when its receipt is ready.");
    };
    let reference = context
        .map_err(anyhow::Error::msg)?
        .and_then(|context| context.model_ref);
    input["threatModelRef"] = serde_json::to_value(reference)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::modules::ToolExecutionContext;
    use kuzushi_core::{OptionScope, OptionTarget, V2Config};

    #[test]
    fn study_options_preview_does_not_read_or_authenticate_saved_scope_objects() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let reference = serde_json::json!({"proposal":{"proposalId":"absent-scope","revision":1,"recordHash":"a".repeat(64)},"scopeId":"repository"});
        app.option_store_mut().set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".into()),
            "scanScopeRef",
            reference.clone(),
        );
        let preview = preview_scan_input(&app).unwrap();
        assert_eq!(preview["scanScopeRef"], reference);
        assert_eq!(preview["triage"], false);
        assert!(app.router.campaign().batch_scan_config.is_none());
    }

    #[test]
    fn study_preview_inherits_exact_accepted_map_and_preserves_explicit_omission() {
        use crate::test_support::{append_typed_attempt, record_indexed_run, select_typed_attempt};
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("reader.py"),
            "print('Offline fixture')\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        let context = ToolExecutionContext {
            config: app.config(),
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let output = app.registry().execute_tool("threat-model:import", serde_json::json!({
            "document":{"version":"1","methodology":"stride","dfd":{"nodes":[{"id":"caller"},{"id":"app"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}
        }), &context).unwrap();
        let mut beta_document = output["data"]["document"].clone();
        beta_document["title"] = serde_json::json!("Globally active Beta");
        let beta = app
            .registry()
            .execute_tool(
                "threat-model:import",
                serde_json::json!({
                    "document": beta_document, "label": "Beta", "activate": true
                }),
                &context,
            )
            .unwrap();
        assert_ne!(beta["data"]["modelRef"], output["data"]["modelRef"]);
        record_indexed_run(
            target.path(),
            "accepted-map",
            "threat-model:import",
            output.clone(),
        );
        let completed = append_typed_attempt(
            target.path(),
            kuzushi_core::WorkflowPhase::Map,
            "accepted-map",
            kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
        );
        select_typed_attempt(target.path(), &completed);
        app.refresh_phase_attempt_projection();
        app.hydrate_all_view_data_for_test();
        let mut input = serde_json::json!({});
        bind_presented_map_context(&app, &mut input).unwrap();
        assert_eq!(input["threatModelRef"], output["data"]["modelRef"]);
        assert_eq!(
            preview_scan_input(&app).unwrap()["threatModelRef"],
            output["data"]["modelRef"]
        );
        input["threatModelRef"] = serde_json::Value::Null;
        bind_presented_map_context(&app, &mut input).unwrap();
        assert!(input["threatModelRef"].is_null());
        record_indexed_run(target.path(), "pending-map", "threat-model:import", beta);
        append_typed_attempt(
            target.path(),
            kuzushi_core::WorkflowPhase::Map,
            "pending-map",
            kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
        );
        app.refresh_phase_attempt_projection();
        app.set_shell_view(crate::app::ShellView::Campaign);
        app.hydrate_all_view_data_for_test();
        let mut pending_input = serde_json::json!({});
        bind_presented_map_context(&app, &mut pending_input).unwrap();
        assert_eq!(pending_input["threatModelRef"], output["data"]["modelRef"]);
        app.option_store_mut().set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".into()),
            "threatModelRef",
            serde_json::Value::Null,
        );
        assert!(preview_scan_input(&app).unwrap()["threatModelRef"].is_null());
        app.workbench_cache()
            .borrow_mut()
            .invalidate_threat_model(target.path());
        assert!(bind_presented_map_context(&app, &mut serde_json::json!({})).is_err());
    }

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
