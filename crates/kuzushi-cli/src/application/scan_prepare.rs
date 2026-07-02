use super::scan::{apply_scan_since_scope, scan_option_store, scan_runtime, scan_tool_input};
use crate::command::ScanModeArg;
use crate::scan_budget::apply_scan_budget_caps;
use anyhow::Result;
use kuzushi_core::run_artifacts::{
    record_tool_run_failed, record_tool_run_started_with_reproducibility, ToolRunRecord,
};
use kuzushi_core::{
    config_hash, load_config_for_target, new_run_id, FindingStore, ModuleRegistry, WorkspaceTarget,
};
use kuzushi_openai::LangGraphRuntime;
use std::path::{Path, PathBuf};

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

pub(crate) fn prepare_scan_command(
    target: &PathBuf,
    mode: Option<ScanModeArg>,
    tasks: &[String],
    triage: Option<bool>,
    budget: Option<&str>,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
) -> Result<PreparedScanCommand> {
    let bootstrap = ScanCommandBootstrap::new(target, mode, tasks, triage)?;
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
    setup.apply_since_scope(since, include_worktree, json, ci)?;
    setup.apply_budget_caps(budget, json, ci)?;
    let input = setup.prepared_input(use_stored_options)?;
    let runtime = setup.runtime(&input)?;
    Ok(setup.into_prepared(store, input, runtime))
}

impl ScanCommandBootstrap {
    fn new(
        target: &PathBuf,
        mode: Option<ScanModeArg>,
        tasks: &[String],
        triage: Option<bool>,
    ) -> Result<Self> {
        Self::from_input(target, scan_tool_input(mode, tasks, triage))
    }

    fn from_input(target: &PathBuf, requested_input: serde_json::Value) -> Result<Self> {
        let registry = ModuleRegistry::with_v2_builtins();
        let run_id = new_run_id("scan");
        let workspace = match WorkspaceTarget::new(target) {
            Ok(workspace) => workspace,
            Err(error) => {
                record_early_scan_prepare_failure(&registry, &run_id, &requested_input, &error)?;
                return Err(error);
            }
        };
        Ok(Self {
            workspace,
            registry,
            run_id,
            requested_input,
        })
    }

    fn load_config_or_record_failure(&self) -> Result<kuzushi_core::V2Config> {
        load_config_for_target(Some(self.workspace.root())).inspect_err(|error| {
            self.record_failure(
                &kuzushi_core::V2Config::default(),
                &self.requested_input,
                error,
            )
        })
    }

    fn with_config(self, config: kuzushi_core::V2Config) -> ScanCommandSetup {
        ScanCommandSetup {
            bootstrap: self,
            config,
        }
    }

    fn record_failure(
        &self,
        config: &kuzushi_core::V2Config,
        input: &serde_json::Value,
        error: &anyhow::Error,
    ) {
        record_scan_prepare_failure(
            &self.workspace,
            &self.registry,
            &self.run_id,
            input,
            config,
            error,
        );
    }
}

impl ScanCommandSetup {
    fn finding_store(&self) -> Result<FindingStore> {
        FindingStore::open(self.bootstrap.workspace.findings_db_path())
            .inspect_err(|error| self.record_failure(&self.bootstrap.requested_input, error))
    }

    fn apply_since_scope(
        &self,
        since: Option<&str>,
        include_worktree: bool,
        json: bool,
        ci: bool,
    ) -> Result<()> {
        apply_scan_since_scope(&self.bootstrap.workspace, since, include_worktree, json, ci)
            .inspect_err(|error| self.record_failure(&self.bootstrap.requested_input, error))
    }

    fn apply_budget_caps(&self, budget: Option<&str>, json: bool, ci: bool) -> Result<()> {
        apply_scan_budget_caps(
            &self.bootstrap.workspace,
            budget,
            self.config.operator.spend_hard_ceiling_usd,
            json,
            ci,
        )
        .inspect_err(|error| self.record_failure(&self.bootstrap.requested_input, error))
    }

    fn prepared_input(&self, use_stored_options: bool) -> Result<serde_json::Value> {
        let option_store = if use_stored_options {
            Some(
                scan_option_store(&self.bootstrap.workspace).inspect_err(|error| {
                    self.record_failure(&self.bootstrap.requested_input, error)
                })?,
            )
        } else {
            None
        };
        self.bootstrap
            .registry
            .prepare_tool_input(
                SCAN_TOOL,
                self.bootstrap.requested_input.clone(),
                option_store.as_ref(),
            )
            .map(|input| scan_input_with_run_id(input, &self.bootstrap.run_id))
            .inspect_err(|error| self.record_failure(&self.bootstrap.requested_input, error))
    }

    fn runtime(&self, input: &serde_json::Value) -> Result<Option<LangGraphRuntime>> {
        scan_runtime(&self.config, input).inspect_err(|error| self.record_failure(input, error))
    }

    fn record_failure(&self, input: &serde_json::Value, error: &anyhow::Error) {
        self.bootstrap.record_failure(&self.config, input, error);
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
) {
    let record = ToolRunRecord::new(workspace.root(), run_id, "scan", SCAN_TOOL);
    record_tool_run_started_with_reproducibility(
        record,
        input,
        config.model.clone(),
        config_hash(config).ok(),
        registry.loaded_module_specifiers(),
    );
    record_tool_run_failed(record, &error.to_string());
}

fn record_early_scan_prepare_failure(
    registry: &ModuleRegistry,
    run_id: &str,
    input: &serde_json::Value,
    error: &anyhow::Error,
) -> Result<()> {
    let target = std::env::current_dir()?;
    record_scan_prepare_failure_at_target(&target, registry, run_id, input, error);
    Ok(())
}

fn record_scan_prepare_failure_at_target(
    target: &Path,
    registry: &ModuleRegistry,
    run_id: &str,
    input: &serde_json::Value,
    error: &anyhow::Error,
) {
    let config = kuzushi_core::V2Config::default();
    let record = ToolRunRecord::new(target, run_id, "scan", SCAN_TOOL);
    record_tool_run_started_with_reproducibility(
        record,
        input,
        config.model.clone(),
        config_hash(&config).ok(),
        registry.loaded_module_specifiers(),
    );
    record_tool_run_failed(record, &error.to_string());
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
}
