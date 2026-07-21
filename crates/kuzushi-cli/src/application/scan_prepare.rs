use super::scan::{apply_scan_since_scope, scan_option_store, scan_runtime, scan_tool_input};
use crate::command::ScanModeArg;
use crate::scan_budget::apply_scan_budget_caps;
use anyhow::Result;
use kuzushi_core::run_artifacts::{
    try_record_tool_run_failed_settled, try_record_tool_run_started_with_reproducibility,
    ToolRunRecord,
};
use kuzushi_core::{
    config_hash, new_run_id, FindingStore, ModuleRegistry, ToolExecutionContext, WorkspaceTarget,
};
use kuzushi_openai::LangGraphRuntime;
use std::path::PathBuf;

pub(crate) const SCAN_TOOL: &str = "sast:scan";

pub(crate) struct PreparedScanCommand {
    pub(crate) workspace: WorkspaceTarget,
    pub(crate) config: kuzushi_core::V2Config,
    pub(crate) store: FindingStore,
    pub(crate) registry: ModuleRegistry,
    pub(crate) input: serde_json::Value,
    pub(crate) runtime: Option<LangGraphRuntime>,
    pub(crate) run_id: String,
}

struct ScanCommandBootstrap {
    workspace: WorkspaceTarget,
    registry: ModuleRegistry,
    run_id: String,
    requested_input: serde_json::Value,
}

struct ScanCommandSetup {
    bootstrap: ScanCommandBootstrap,
    config: kuzushi_core::V2Config,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_scan_command(
    target: &PathBuf,
    mode: Option<ScanModeArg>,
    tasks: &[String],
    triage: Option<bool>,
    budget: Option<&str>,
    scope: &super::scan::ScanScopeArgs,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
) -> Result<PreparedScanCommand> {
    let bootstrap = ScanCommandBootstrap::new(target, mode, tasks, triage, scope)?;
    prepare_scan_command_from_bootstrap(bootstrap, budget, since, include_worktree, json, ci, true)
}

pub(crate) fn prepare_scan_command_with_requested_input(
    target: &PathBuf,
    requested_input: serde_json::Value,
    json: bool,
    ci: bool,
) -> Result<PreparedScanCommand> {
    let bootstrap = ScanCommandBootstrap::from_input(target, requested_input)?;
    prepare_scan_command_from_bootstrap(bootstrap, None, None, false, json, ci, false)
}

fn prepare_scan_command_from_bootstrap(
    bootstrap: ScanCommandBootstrap,
    budget: Option<&str>,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
    use_stored_options: bool,
) -> Result<PreparedScanCommand> {
    let config = bootstrap.load_config_or_record_failure()?;
    let setup = bootstrap.with_config(config);
    let store = setup.finding_store()?;
    setup.prepare_workspace_state(&store)?;
    setup.apply_since_scope(since, include_worktree, json, ci)?;
    setup.apply_budget_caps(budget, json, ci)?;
    let input = setup.prepared_input(use_stored_options, &store)?;
    let runtime = setup.runtime(&input)?;
    Ok(setup.into_prepared(store, input, runtime))
}

impl ScanCommandBootstrap {
    fn new(
        target: &PathBuf,
        mode: Option<ScanModeArg>,
        tasks: &[String],
        triage: Option<bool>,
        scope: &super::scan::ScanScopeArgs,
    ) -> Result<Self> {
        let mut requested_input = scan_tool_input(mode, tasks, triage);
        super::scan_shards::apply_scan_paths_scope(
            &mut requested_input,
            target,
            scope.shard.as_deref(),
            scope.shard_manifest.as_deref(),
            &scope.paths,
        )?;
        Self::from_input(target, requested_input)
    }

    fn from_input(target: &PathBuf, requested_input: serde_json::Value) -> Result<Self> {
        let registry = ModuleRegistry::with_v2_builtins();
        let run_id = new_run_id("scan");
        let workspace = WorkspaceTarget::new(target)?;
        workspace.ensure_state_dir()?;
        Ok(Self {
            workspace,
            registry,
            run_id,
            requested_input,
        })
    }

    fn load_config_or_record_failure(&self) -> Result<kuzushi_core::V2Config> {
        super::config_diagnostics::load_cli_config(Some(self.workspace.root())).map_err(|error| {
            self.recorded_error(
                error,
                &kuzushi_core::V2Config::default(),
                &self.requested_input,
            )
        })
    }

    fn with_config(self, config: kuzushi_core::V2Config) -> ScanCommandSetup {
        ScanCommandSetup {
            bootstrap: self,
            config,
        }
    }

    fn recorded_error(
        &self,
        error: anyhow::Error,
        config: &kuzushi_core::V2Config,
        input: &serde_json::Value,
    ) -> anyhow::Error {
        let persistence = record_scan_prepare_failure(
            &self.workspace,
            &self.registry,
            &self.run_id,
            input,
            config,
            &error,
        );
        match persistence {
            Ok(()) => {
                crate::presentation::scan_error_with_recovery(error, &self.workspace, &self.run_id)
            }
            Err(persistence) => error_with_persistence(error, Err(persistence)),
        }
    }
}

impl ScanCommandSetup {
    fn finding_store(&self) -> Result<FindingStore> {
        FindingStore::open(self.bootstrap.workspace.findings_db_path())
            .map_err(|error| self.recorded_error(error, &self.bootstrap.requested_input))
    }

    fn prepare_workspace_state(&self, store: &FindingStore) -> Result<()> {
        let preparation =
            kuzushi_core::scan::prepare_scan_workspace_state(&self.bootstrap.workspace, store)
                .map_err(|error| self.recorded_error(error, &self.bootstrap.requested_input))?;
        if let Some(warning) = &preparation.tree_identity_warning {
            eprintln!("warning: {warning}");
        }
        let summary = &preparation.suppressions;
        if !summary.is_noop() {
            eprintln!(
                "suppressions: {} added, {} reopened by expiry, {} reopened by rule removal",
                summary.added, summary.expired, summary.removed
            );
        }
        Ok(())
    }

    fn apply_since_scope(
        &self,
        since: Option<&str>,
        include_worktree: bool,
        json: bool,
        ci: bool,
    ) -> Result<()> {
        apply_scan_since_scope(&self.bootstrap.workspace, since, include_worktree, json, ci)
            .map_err(|error| self.recorded_error(error, &self.bootstrap.requested_input))
    }

    fn apply_budget_caps(&self, budget: Option<&str>, json: bool, ci: bool) -> Result<()> {
        apply_scan_budget_caps(
            &self.bootstrap.workspace,
            budget,
            self.config.operator.spend_hard_ceiling_usd,
            json,
            ci,
        )
        .map_err(|error| self.recorded_error(error, &self.bootstrap.requested_input))
    }

    fn prepared_input(
        &self,
        use_stored_options: bool,
        store: &FindingStore,
    ) -> Result<serde_json::Value> {
        let option_store = if use_stored_options {
            Some(
                scan_option_store(&self.bootstrap.workspace)
                    .map_err(|error| self.recorded_error(error, &self.bootstrap.requested_input))?,
            )
        } else {
            None
        };
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.bootstrap.workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        self.bootstrap
            .registry
            .prepare_tool_input_for_dispatch(
                SCAN_TOOL,
                self.bootstrap.requested_input.clone(),
                &ctx,
                option_store.as_ref(),
            )
            .map(|input| scan_input_with_run_id(input, &self.bootstrap.run_id))
            .map_err(|error| self.recorded_error(error, &self.bootstrap.requested_input))
    }

    fn runtime(&self, input: &serde_json::Value) -> Result<Option<LangGraphRuntime>> {
        scan_runtime(&self.config, input, &self.bootstrap.workspace)
            .map_err(|error| self.recorded_error(error, input))
    }

    fn recorded_error(&self, error: anyhow::Error, input: &serde_json::Value) -> anyhow::Error {
        self.bootstrap.recorded_error(error, &self.config, input)
    }

    fn into_prepared(
        self,
        store: FindingStore,
        input: serde_json::Value,
        runtime: Option<LangGraphRuntime>,
    ) -> PreparedScanCommand {
        PreparedScanCommand {
            workspace: self.bootstrap.workspace,
            config: self.config,
            store,
            registry: self.bootstrap.registry,
            input,
            runtime,
            run_id: self.bootstrap.run_id,
        }
    }
}

fn scan_input_with_run_id(mut input: serde_json::Value, run_id: &str) -> serde_json::Value {
    if let serde_json::Value::Object(object) = &mut input {
        object.insert("runId".to_string(), serde_json::json!(run_id));
    }
    input
}

fn record_scan_prepare_failure(
    workspace: &WorkspaceTarget,
    registry: &ModuleRegistry,
    run_id: &str,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
    error: &anyhow::Error,
) -> Result<()> {
    let record = ToolRunRecord::new(workspace.root(), run_id, "scan", SCAN_TOOL);
    try_record_tool_run_started_with_reproducibility(
        record,
        input,
        kuzushi_core::tool_execution_model(SCAN_TOOL, input, config),
        config_hash(config).ok(),
        registry.loaded_module_specifiers(),
    )?;
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(workspace.root(), run_id)?;
    let rejection = kuzushi_core::run_lifecycle::observe_preparation_rejection(
        &observation,
        SCAN_TOOL,
        input,
        "preparation_policy",
        &error.to_string(),
    )?;
    let (observation, completion) = rejection.into_parts();
    try_record_tool_run_failed_settled(record, &error.to_string(), &observation, completion)
}

fn error_with_persistence(error: anyhow::Error, persistence: Result<()>) -> anyhow::Error {
    match persistence {
        Ok(()) => error,
        Err(persistence) => anyhow::anyhow!(
            "{error:#}; additionally, run artifact persistence failed: {persistence:#}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_input_with_run_id_adds_internal_artifact_identity() {
        let input = scan_input_with_run_id(serde_json::json!({"triage": true}), "scan-123");

        assert_eq!(input["runId"], serde_json::json!("scan-123"));
        assert_eq!(input["triage"], serde_json::json!(true));
    }

    #[test]
    fn prepare_error_keeps_secondary_persistence_failure() {
        let error = error_with_persistence(
            anyhow::anyhow!("invalid target"),
            Err(anyhow::anyhow!("ledger unavailable")),
        )
        .to_string();

        assert!(error.contains("invalid target"), "{error}");
        assert!(error.contains("run artifact persistence failed"), "{error}");
        assert!(error.contains("ledger unavailable"), "{error}");
    }

    #[test]
    fn scan_prepare_commits_workspace_snapshot_before_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("src/app.rs"), "fn main() {}\n").unwrap();

        let prepared = prepare_scan_command_with_requested_input(
            &tmp.path().to_path_buf(),
            serde_json::json!({"triage": false}),
            true,
            true,
        )
        .unwrap();
        drop(prepared);

        assert!(tmp.path().join(".kuzushi/.gitignore").is_file());
        let log =
            kuzushi_core::event_log::EventLog::open(tmp.path().join(".kuzushi/v3/log")).unwrap();
        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].event_kind,
            kuzushi_core::event_log::EventKind::SnapshotIndexed
        );
        assert_eq!(
            events[1].event_kind,
            kuzushi_core::event_log::EventKind::FileIndexed
        );
    }

    #[test]
    fn scan_prepare_rejection_has_failed_task_call_and_exact_artifacts() {
        let target = tempfile::tempdir().unwrap();
        let error = prepare_scan_command_with_requested_input(
            &target.path().to_path_buf(),
            serde_json::json!({"unknownOption": true}),
            true,
            true,
        )
        .err()
        .expect("unknown option must be rejected");
        assert!(error.to_string().contains("unknown"));

        let entry = kuzushi_core::list_recent_run_summary_entries(target.path(), 1)
            .unwrap()
            .pop()
            .unwrap();
        let read =
            kuzushi_core::run_lifecycle::load_run_projection(target.path(), &entry.run_id).unwrap();
        let call = read.projection.calls.values().next().unwrap();
        assert_eq!(
            call.status,
            kuzushi_core::run_lifecycle::RunItemStatus::Failed
        );
        assert_eq!(
            read.projection.terminal.as_ref().map(|item| item.status),
            Some(kuzushi_core::run_lifecycle::RunItemStatus::Failed)
        );
        assert!(read
            .projection
            .artifacts
            .values()
            .all(|artifact| artifact.producing_item_id == call.item_id));
        assert_eq!(
            call.result_artifact
                .as_ref()
                .map(|artifact| artifact.path.as_str()),
            Some("result.json")
        );
    }
}
