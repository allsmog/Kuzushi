use super::run_tool::run_option_store;
use crate::dispatch::load_dynamic_modules;
use crate::tool_requirements::{
    reject_shell_only_run_dot, run_tool_workspace_for_input, tool_needs_finding_store,
};
use crate::tool_run_artifacts::fail_cli_tool_run;
use anyhow::Result;
use kuzushi_core::run_artifacts::{record_tool_run_started_with_reproducibility, ToolRunRecord};
use kuzushi_core::{
    config_hash, load_config_for_target, new_run_id, FindingStore, ModuleRegistry,
    ToolExecutionContext, ToolOptionStore, WorkspaceTarget,
};
use std::path::{Path, PathBuf};

pub(crate) struct PreparedCliToolRun {
    pub(crate) tool: String,
    pub(crate) workspace: Option<WorkspaceTarget>,
    pub(crate) config: kuzushi_core::V2Config,
    pub(crate) store: Option<FindingStore>,
    pub(crate) registry: ModuleRegistry,
    pub(crate) input: serde_json::Value,
    pub(crate) artifact_target: PathBuf,
    pub(crate) run_id: String,
}

struct CliToolRunSetup {
    tool: String,
    workspace: Option<WorkspaceTarget>,
    config: kuzushi_core::V2Config,
    registry: ModuleRegistry,
    artifact_target: PathBuf,
    run_id: String,
}

struct CliToolRunBootstrap {
    tool: String,
    workspace: Option<WorkspaceTarget>,
    registry: ModuleRegistry,
    artifact_target: PathBuf,
    run_id: String,
}

pub(crate) fn prepare_cli_tool_run(
    tool: String,
    input: String,
    options: Vec<String>,
    target: Option<PathBuf>,
    load: Vec<String>,
) -> Result<PreparedCliToolRun> {
    let bootstrap = CliToolRunBootstrap::new(tool, target, &input)?;
    let config = bootstrap.load_config_or_record_failure(&input)?;
    let setup = bootstrap.with_config(config, load, &input)?;
    let input = setup.parse_input(&input)?;
    let option_store = setup.option_store(&input, &options)?;
    let input = setup.prepare_input(input, &option_store)?;
    let store = setup.finding_store(&input)?;
    setup.start(&input);
    Ok(setup.into_prepared(input, store))
}

#[cfg(test)]
pub(crate) fn start_cli_tool_run_with_loaded_modules(
    target: &Path,
    tool: &str,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
    loaded_modules: Vec<String>,
) -> String {
    let run_id = new_run_id("run");
    record_cli_tool_run_started(target, &run_id, tool, input, config, loaded_modules);
    run_id
}

impl CliToolRunBootstrap {
    fn new(tool: String, target: Option<PathBuf>, raw_input: &str) -> Result<Self> {
        let registry = ModuleRegistry::with_v2_builtins();
        let run_id = new_run_id("run");
        let workspace = match run_tool_workspace_for_input(&tool, target.as_deref(), raw_input) {
            Ok(workspace) => workspace,
            Err(error) => {
                record_early_prepare_failure(&run_id, &tool, raw_input, &error.to_string())?;
                return Err(error);
            }
        };
        let artifact_target = cli_tool_run_artifact_target(workspace.as_ref())?;
        Ok(Self {
            tool,
            workspace,
            registry,
            artifact_target,
            run_id,
        })
        .and_then(|bootstrap| bootstrap.reject_shell_only_or_record_failure(raw_input))
    }

    fn load_config_or_record_failure(&self, raw_input: &str) -> Result<kuzushi_core::V2Config> {
        load_config_for_target(self.workspace.as_ref().map(WorkspaceTarget::root))
            .inspect_err(|error| self.record_config_failure(raw_input, &error.to_string()))
    }

    fn record_config_failure(&self, raw_input: &str, error: &str) {
        self.record_pre_config_failure(raw_input, error);
    }

    fn reject_shell_only_or_record_failure(self, raw_input: &str) -> Result<Self> {
        if let Err(error) = reject_shell_only_run_dot(&self.tool) {
            self.record_pre_config_failure(raw_input, &error.to_string());
            return Err(error);
        }
        Ok(self)
    }

    fn record_pre_config_failure(&self, raw_input: &str, error: &str) {
        record_cli_tool_run_started(
            &self.artifact_target,
            &self.run_id,
            &self.tool,
            &serde_json::json!({ "rawInput": raw_input }),
            &kuzushi_core::V2Config::default(),
            self.registry.loaded_module_specifiers(),
        );
        fail_cli_tool_run(&self.artifact_target, &self.run_id, &self.tool, error);
    }

    fn with_config(
        mut self,
        config: kuzushi_core::V2Config,
        load: Vec<String>,
        raw_input: &str,
    ) -> Result<CliToolRunSetup> {
        if let Err(error) = load_dynamic_modules(&mut self.registry, &config, &load) {
            self.record_pre_config_failure(raw_input, &error.to_string());
            return Err(error);
        }
        Ok(CliToolRunSetup {
            tool: self.tool,
            workspace: self.workspace,
            config,
            registry: self.registry,
            artifact_target: self.artifact_target,
            run_id: self.run_id,
        })
    }
}

impl CliToolRunSetup {
    fn parse_input(&self, input: &str) -> Result<serde_json::Value> {
        match serde_json::from_str(input) {
            Ok(input) => Ok(input),
            Err(error) => {
                let error = anyhow::Error::new(error).context("--input must be JSON");
                self.record_prepare_failure(&serde_json::json!({ "rawInput": input }), &error);
                Err(error)
            }
        }
    }

    fn option_store(
        &self,
        input: &serde_json::Value,
        options: &[String],
    ) -> Result<ToolOptionStore> {
        run_option_store(self.workspace.as_ref(), &self.tool, options)
            .inspect_err(|error| self.record_prepare_failure(input, error))
    }

    fn prepare_input(
        &self,
        input: serde_json::Value,
        option_store: &ToolOptionStore,
    ) -> Result<serde_json::Value> {
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: self.workspace.as_ref(),
            findings_store: None,
            trace: None,
        };
        self.registry
            .prepare_tool_input_for_dispatch(&self.tool, input.clone(), &ctx, Some(option_store))
            .inspect_err(|error| self.record_prepare_failure(&input, error))
    }

    fn finding_store(&self, input: &serde_json::Value) -> Result<Option<FindingStore>> {
        open_cli_tool_finding_store(self.workspace.as_ref(), &self.tool)
            .inspect_err(|error| self.record_prepare_failure(input, error))
    }

    fn start(&self, input: &serde_json::Value) {
        record_cli_tool_run_started(
            &self.artifact_target,
            &self.run_id,
            &self.tool,
            input,
            &self.config,
            self.registry.loaded_module_specifiers(),
        );
    }

    fn record_prepare_failure(&self, input: &serde_json::Value, error: &anyhow::Error) {
        self.start(input);
        fail_cli_tool_run(
            &self.artifact_target,
            &self.run_id,
            &self.tool,
            &error.to_string(),
        );
    }

    fn into_prepared(
        self,
        input: serde_json::Value,
        store: Option<FindingStore>,
    ) -> PreparedCliToolRun {
        PreparedCliToolRun {
            tool: self.tool,
            workspace: self.workspace,
            config: self.config,
            store,
            registry: self.registry,
            input,
            artifact_target: self.artifact_target,
            run_id: self.run_id,
        }
    }
}

fn open_cli_tool_finding_store(
    workspace: Option<&WorkspaceTarget>,
    tool: &str,
) -> Result<Option<FindingStore>> {
    workspace
        .filter(|_| tool_needs_finding_store(tool))
        .map(|workspace| FindingStore::open(workspace.findings_db_path()))
        .transpose()
}

fn cli_tool_run_artifact_target(workspace: Option<&WorkspaceTarget>) -> Result<PathBuf> {
    match workspace {
        Some(workspace) => Ok(workspace.root().to_path_buf()),
        None => Ok(std::env::current_dir()?),
    }
}

fn record_early_prepare_failure(
    run_id: &str,
    tool: &str,
    raw_input: &str,
    error: &str,
) -> Result<()> {
    let target = std::env::current_dir()?;
    record_cli_tool_run_started(
        &target,
        run_id,
        tool,
        &serde_json::json!({ "rawInput": raw_input }),
        &kuzushi_core::V2Config::default(),
        ModuleRegistry::with_v2_builtins().loaded_module_specifiers(),
    );
    fail_cli_tool_run(&target, run_id, tool, error);
    Ok(())
}

fn record_cli_tool_run_started(
    target: &Path,
    run_id: &str,
    tool: &str,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
    loaded_modules: Vec<String>,
) {
    record_tool_run_started_with_reproducibility(
        ToolRunRecord::new(target, run_id, "run", tool),
        input,
        config.model.clone(),
        config_hash(config).ok(),
        loaded_modules,
    );
}
