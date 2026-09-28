use super::run_tool::run_option_store;
use crate::dispatch::load_dynamic_modules;
use crate::tool_requirements::{reject_shell_only_run_dot, run_tool_workspace_for_invocation};
use anyhow::Result;
use kuzushi_core::run_artifacts::{
    try_record_tool_run_failed_settled, try_record_tool_run_started_with_reproducibility,
    ToolRunRecord,
};
use kuzushi_core::{
    config_hash, new_run_id, AutonomyPosture, FindingStore, ModuleRegistry, PreparedToolInput,
    ToolExecutionContext, ToolOptionStore, WorkspaceTarget,
};
use std::path::{Path, PathBuf};

pub(crate) struct PreparedCliToolRun {
    pub(crate) tool: String,
    pub(crate) task_title: String,
    pub(crate) workspace: Option<WorkspaceTarget>,
    pub(crate) config: kuzushi_core::V2Config,
    pub(crate) store: Option<FindingStore>,
    pub(crate) registry: ModuleRegistry,
    pub(crate) input: PreparedToolInput,
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

/// `target` arrives pre-resolved by `resolve_run_target` (the shared
/// `target_or_global` precedence policy); this function only constructs the
/// workspace and never substitutes cwd for a missing target.
pub(crate) fn prepare_cli_tool_run(
    tool: String,
    input: String,
    options: Vec<String>,
    autonomy: Option<String>,
    target: Option<PathBuf>,
    load: Vec<String>,
    explicit_run_id: Option<String>,
) -> Result<PreparedCliToolRun> {
    let bootstrap =
        CliToolRunBootstrap::new(tool, target, &input, &options, &load, explicit_run_id)?;
    let mut config = bootstrap.load_config_or_record_failure(&input)?;
    config.autonomy = bootstrap.resolve_autonomy_or_record_failure(&config, autonomy, &input)?;
    let setup = bootstrap.with_config(config, load, &input)?;
    let input = setup.parse_input(&input)?;
    let option_store = setup.option_store(&input, &options)?;
    let input = setup.prepare_input(input, &option_store)?;
    let store = setup.finding_store(&input)?;
    setup.start(input.value())?;
    Ok(setup.into_prepared(input, store))
}

/// A caller-supplied run id must be filesystem-safe and unused, so the
/// caller (the campaign dispatcher) can rely on `.kuzushi/v3/runs/<id>/`
/// being exclusively this run's artifacts. A collision is a prepare-stage
/// error (batch exit 2): retrying the same id is pointless by design.
fn validated_explicit_run_id(explicit: String, target: Option<&Path>) -> Result<String> {
    let id = explicit.trim().to_string();
    anyhow::ensure!(
        !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "--run-id may only contain ASCII alphanumerics, '-', and '_', got {explicit:?}"
    );
    if let Some(target) = target {
        let run_dir = kuzushi_core::run_dir(target, &id);
        anyhow::ensure!(
            !run_dir.exists(),
            "--run-id {id:?} already has artifacts at {}",
            run_dir.display()
        );
    }
    Ok(id)
}

/// Resolve the `--autonomy` flag into the run's posture. Absent = the config
/// default (`Fix`, unconstrained). An explicit rung is clamped by the
/// project-declared `phases.stop_after` cap (with a stderr note when clamping
/// actually changes the requested rung — mirrors the TUI's "posture stays
/// at…" log so the operator isn't silently overridden), and an unrecognized
/// rung is a hard error — never a silent fallback to a different rung.
fn resolve_cli_autonomy(
    config: &kuzushi_core::V2Config,
    autonomy: Option<String>,
) -> Result<AutonomyPosture> {
    let Some(raw) = autonomy else {
        return Ok(config.autonomy);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "hunt" => eprintln!("warning: --autonomy hunt is deprecated; use scan"),
        "confirm" => eprintln!("warning: --autonomy confirm is deprecated; use prove"),
        _ => {}
    }
    let posture = AutonomyPosture::parse(&raw).ok_or_else(|| {
        anyhow::anyhow!(
            "--autonomy must be one of recon|scan|review|prove|fix (hunt and confirm are deprecated aliases), got {raw:?}"
        )
    })?;
    let cap = config
        .phases
        .stop_after
        .map(AutonomyPosture::from_guided_phase)
        .unwrap_or(AutonomyPosture::Fix);
    let applied = posture.capped_by(cap);
    if applied != posture {
        eprintln!(
            "autonomy: --autonomy {} clamped to {} by phases.stop_after={}",
            posture.label(),
            applied.label(),
            cap.label()
        );
    }
    Ok(applied)
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
    record_cli_tool_run_started(target, &run_id, tool, input, config, loaded_modules)
        .expect("test run should persist its start record");
    run_id
}

impl CliToolRunBootstrap {
    fn new(
        tool: String,
        target: Option<PathBuf>,
        raw_input: &str,
        options: &[String],
        load: &[String],
        explicit_run_id: Option<String>,
    ) -> Result<Self> {
        let registry = ModuleRegistry::with_v2_builtins();
        let run_id = match explicit_run_id {
            Some(explicit) => validated_explicit_run_id(explicit, target.as_deref())?,
            None => new_run_id("run"),
        };
        require_dynamic_invocation_workspace(&registry, &tool, target.as_deref(), load)?;
        let workspace = run_tool_workspace_for_invocation(
            &registry,
            &tool,
            target.as_deref(),
            raw_input,
            options,
        )?;
        let artifact_target = cli_tool_run_artifact_target(workspace.as_ref())?;
        initialize_cli_artifact_target(&artifact_target)?;
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
        super::config_diagnostics::load_cli_config(
            self.workspace.as_ref().map(WorkspaceTarget::root),
        )
        .map_err(|error| {
            let message = error.to_string();
            error_with_persistence(error, self.record_pre_config_failure(raw_input, &message))
        })
    }

    fn resolve_autonomy_or_record_failure(
        &self,
        config: &kuzushi_core::V2Config,
        autonomy: Option<String>,
        raw_input: &str,
    ) -> Result<AutonomyPosture> {
        resolve_cli_autonomy(config, autonomy).map_err(|error| {
            let message = error.to_string();
            error_with_persistence(
                error,
                self.record_failure_with_config(raw_input, config, &message),
            )
        })
    }

    fn reject_shell_only_or_record_failure(self, raw_input: &str) -> Result<Self> {
        if let Err(error) = reject_shell_only_run_dot(&self.tool) {
            let message = error.to_string();
            return Err(error_with_persistence(
                error,
                self.record_pre_config_failure(raw_input, &message),
            ));
        }
        Ok(self)
    }

    fn record_pre_config_failure(&self, raw_input: &str, error: &str) -> Result<()> {
        self.record_failure_with_config(raw_input, &kuzushi_core::V2Config::default(), error)
    }

    fn record_failure_with_config(
        &self,
        raw_input: &str,
        config: &kuzushi_core::V2Config,
        error: &str,
    ) -> Result<()> {
        let input = serde_json::json!({ "rawInput": raw_input });
        record_cli_tool_run_started(
            &self.artifact_target,
            &self.run_id,
            &self.tool,
            &input,
            config,
            self.registry.loaded_module_specifiers(),
        )?;
        record_cli_preparation_rejection(
            &self.artifact_target,
            &self.run_id,
            &self.tool,
            &input,
            error,
        )
    }

    fn with_config(
        mut self,
        config: kuzushi_core::V2Config,
        load: Vec<String>,
        raw_input: &str,
    ) -> Result<CliToolRunSetup> {
        if let Err(error) = load_dynamic_modules(&mut self.registry, &config, &load) {
            let message = error.to_string();
            return Err(error_with_persistence(
                error,
                self.record_pre_config_failure(raw_input, &message),
            ));
        }
        if let Err(error) = require_headless_run_tool(&self.registry, &self.tool) {
            let message = error.to_string();
            return Err(error_with_persistence(
                error,
                self.record_pre_config_failure(raw_input, &message),
            ));
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

fn initialize_cli_artifact_target(target: &Path) -> Result<()> {
    WorkspaceTarget::new(target)?.ensure_state_dir()?;
    Ok(())
}

fn require_dynamic_invocation_workspace(
    registry: &ModuleRegistry,
    tool: &str,
    target: Option<&Path>,
    load: &[String],
) -> Result<()> {
    if load.is_empty() || registry.resolve_tool(tool).is_some() || target.is_some() {
        return Ok(());
    }
    anyhow::bail!(
        "dynamic tools loaded with --load require an explicit global --target <workspace>; Kuzushi must load their descriptor through that workspace's trusted-module policy before interpreting path options"
    )
}

fn require_headless_run_tool(registry: &ModuleRegistry, tool_name: &str) -> Result<()> {
    let Some(tool) = registry.resolve_tool(tool_name) else {
        return Ok(());
    };
    if tool.headless {
        return Ok(());
    }
    anyhow::bail!("{tool_name} is shell-only (headless=false) and cannot run through `kuzushi run`")
}

impl CliToolRunSetup {
    fn parse_input(&self, input: &str) -> Result<serde_json::Value> {
        match serde_json::from_str(input) {
            Ok(input) => Ok(input),
            Err(error) => {
                let error = anyhow::Error::new(error).context(
                    "--input must contain structured JSON; use --option key=value for ordinary options",
                );
                let persisted = self.record_prepare_failure(
                    &serde_json::json!({ "rawInput": input }),
                    &error.to_string(),
                );
                Err(error_with_persistence(error, persisted))
            }
        }
    }

    fn option_store(
        &self,
        input: &serde_json::Value,
        options: &[String],
    ) -> Result<ToolOptionStore> {
        self.declared_option_overrides(options)
            .and_then(|()| run_option_store(self.workspace.as_ref(), &self.tool, options))
            .map_err(|error| {
                let message = error.to_string();
                error_with_persistence(error, self.record_prepare_failure(input, &message))
            })
    }

    /// `--option` names must be declared by the tool, exactly as `--input`
    /// keys are; a typo is refused instead of silently dropped.
    fn declared_option_overrides(&self, options: &[String]) -> Result<()> {
        let Some(tool) = self.registry.resolve_tool(&self.tool) else {
            return Ok(());
        };
        for option in options {
            let (name, _) = super::run_tool::parse_option_override(option)?;
            kuzushi_core::modules::ensure_declared_tool_option(tool, &name)?;
        }
        Ok(())
    }

    fn prepare_input(
        &self,
        input: serde_json::Value,
        option_store: &ToolOptionStore,
    ) -> Result<PreparedToolInput> {
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: self.workspace.as_ref(),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        self.registry
            .prepare_dispatch_input(&self.tool, input.clone(), &ctx, Some(option_store))
            .map_err(|error| {
                let message = error.to_string();
                error_with_persistence(error, self.record_prepare_failure(&input, &message))
            })
    }

    fn finding_store(&self, input: &PreparedToolInput) -> Result<Option<FindingStore>> {
        open_cli_tool_finding_store(self.workspace.as_ref(), &self.registry, &self.tool).map_err(
            |error| {
                let message = error.to_string();
                error_with_persistence(error, self.record_prepare_failure(input.value(), &message))
            },
        )
    }

    fn start(&self, input: &serde_json::Value) -> Result<()> {
        try_record_tool_run_started_with_reproducibility(
            ToolRunRecord::new(&self.artifact_target, &self.run_id, "run", &self.tool),
            input,
            kuzushi_core::tool_execution_model(&self.tool, input, &self.config),
            config_hash(&self.config).ok(),
            self.registry.loaded_module_specifiers(),
        )
    }

    fn record_prepare_failure(&self, input: &serde_json::Value, error: &str) -> Result<()> {
        self.start(input)?;
        record_cli_preparation_rejection(
            &self.artifact_target,
            &self.run_id,
            &self.tool,
            input,
            error,
        )
    }

    fn into_prepared(
        self,
        input: PreparedToolInput,
        store: Option<FindingStore>,
    ) -> PreparedCliToolRun {
        let task_title = direct_tool_intent(&self.registry, &self.tool);
        PreparedCliToolRun {
            tool: self.tool,
            task_title,
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

fn direct_tool_intent(registry: &ModuleRegistry, tool: &str) -> String {
    registry
        .resolve_tool(tool)
        .map(|descriptor| descriptor.description.trim())
        .filter(|description| !description.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "Execute the operator-selected security capability".to_string())
}

fn open_cli_tool_finding_store(
    workspace: Option<&WorkspaceTarget>,
    registry: &ModuleRegistry,
    tool: &str,
) -> Result<Option<FindingStore>> {
    workspace
        .filter(|_| registry.tool_requires_finding_store(tool))
        .map(|workspace| FindingStore::open(workspace.findings_db_path()))
        .transpose()
}

fn cli_tool_run_artifact_target(workspace: Option<&WorkspaceTarget>) -> Result<PathBuf> {
    match workspace {
        Some(workspace) => Ok(workspace.root().to_path_buf()),
        // Intentional run-mode behavior: tools whose descriptor does not need
        // a workspace still receive a durable run bundle rooted at the
        // directory from which the operator invoked `kuzushi run`.
        None => Ok(std::env::current_dir()?),
    }
}

fn record_cli_tool_run_started(
    target: &Path,
    run_id: &str,
    tool: &str,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
    loaded_modules: Vec<String>,
) -> Result<()> {
    try_record_tool_run_started_with_reproducibility(
        ToolRunRecord::new(target, run_id, "run", tool),
        input,
        kuzushi_core::tool_execution_model(tool, input, config),
        config_hash(config).ok(),
        loaded_modules,
    )
}

fn record_cli_preparation_rejection(
    target: &Path,
    run_id: &str,
    tool: &str,
    input: &serde_json::Value,
    error: &str,
) -> Result<()> {
    let observation = kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, run_id)?;
    let rejection = kuzushi_core::run_lifecycle::observe_preparation_rejection(
        &observation,
        tool,
        input,
        "preparation_policy",
        error,
    )?;
    let (observation, completion) = rejection.into_parts();
    let recorded = try_record_tool_run_failed_settled(
        ToolRunRecord::new(target, run_id, "run", tool),
        error,
        &observation,
        completion,
    );
    // Sentinel presence is reserved for a verified durable terminal bundle.
    if recorded.is_ok() {
        let sentinel =
            kuzushi_core::load_persisted_run_terminal_outcome(target, run_id).and_then(|outcome| {
                super::run_exit::write_done_sentinel(
                    target,
                    run_id,
                    tool,
                    outcome.status,
                    super::run_exit::run_exit_code(outcome.status),
                )
                .map(|_| ())
            });
        if let Err(error) = sentinel {
            eprintln!("kuzushi: warning: done sentinel not written: {error}");
        }
    }
    recorded
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
mod resolve_cli_autonomy_tests {
    use super::{
        direct_tool_intent, error_with_persistence, prepare_cli_tool_run,
        record_cli_tool_run_started, require_headless_run_tool, resolve_cli_autonomy,
    };
    use kuzushi_core::{
        approve_dynamic_module, worker_protocol::Grant, AutonomyPosture, DynamicModuleLoadOptions,
        GuidedPhase, ModuleRegistry, V2Config,
    };

    fn decode_first_repo_record(prompt: &str) -> kuzushi_core::prompts::UntrustedRecord {
        let start = prompt
            .find(kuzushi_core::prompts::UNTRUSTED_REPO_BEGIN)
            .unwrap();
        let framed = &prompt[start..];
        let end = framed
            .find(kuzushi_core::prompts::UNTRUSTED_REPO_END)
            .unwrap()
            + kuzushi_core::prompts::UNTRUSTED_REPO_END.len();
        kuzushi_core::prompts::decode_untrusted_record(&framed[..end]).unwrap()
    }

    #[test]
    fn absent_flag_keeps_the_config_default() {
        let config = V2Config::default();
        assert_eq!(
            resolve_cli_autonomy(&config, None).unwrap(),
            config.autonomy
        );
    }

    #[test]
    fn direct_run_task_uses_descriptor_intent_instead_of_tool_identity() {
        let registry = ModuleRegistry::with_v2_builtins();
        let title = direct_tool_intent(&registry, "workspace:status");

        assert_ne!(title, "Run workspace:status");
        assert_eq!(
            title,
            registry
                .resolve_tool("workspace:status")
                .unwrap()
                .description
                .trim()
        );
    }

    #[test]
    fn explicit_rung_under_the_cap_is_applied_unchanged() {
        let mut config = V2Config::default();
        config.phases.stop_after = Some(GuidedPhase::Fix);
        assert_eq!(
            resolve_cli_autonomy(&config, Some("hunt".to_string())).unwrap(),
            AutonomyPosture::Scan
        );
    }

    #[test]
    fn explicit_rung_above_the_cap_is_clamped() {
        let mut config = V2Config::default();
        config.phases.stop_after = Some(GuidedPhase::Scan);
        assert_eq!(
            resolve_cli_autonomy(&config, Some("fix".to_string())).unwrap(),
            AutonomyPosture::Scan
        );
    }

    #[test]
    fn unrecognized_rung_is_a_hard_error() {
        let config = V2Config::default();
        assert!(resolve_cli_autonomy(&config, Some("nonsense".to_string())).is_err());
        assert!(resolve_cli_autonomy(&config, Some("2".to_string())).is_err());
    }

    #[test]
    fn run_rejects_dynamic_shell_only_tools_after_loading_their_descriptor() {
        if !kuzushi_core::modules::kwp_node_execution_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("shell-only.mjs");
        write_shell_only_module(&module_path);
        let specifier = format!("file://{}", module_path.display());
        let lockfile_path = tmp.path().join("kuzushi.lock");
        approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path).unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    trusted_specifiers: vec![specifier.clone()],
                    lockfile_path: Some(lockfile_path),
                },
            )
            .unwrap();

        let error = require_headless_run_tool(&registry, "shell-only:open")
            .unwrap_err()
            .to_string();

        assert!(error.contains("headless=false"), "{error}");
    }

    fn write_shell_only_module(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"
export default {
  id: "shell-only",
  displayName: "Shell Only",
  category: "internal",
  description: "interactive tool",
  tools: [{
    name: "shell-only:open",
    description: "open an interactive surface",
    headless: false,
    effect: "read",
    approval: "none",
    workspaceRequirement: "optional",
    options: [],
    run() { return { status: "completed" }; }
  }]
};
"#,
        )
        .unwrap();
    }

    #[test]
    fn inline_target_drives_cli_workspace_store_and_artifact_root() {
        let target = tempfile::tempdir().unwrap();
        let raw_input = serde_json::json!({ "target": target.path() }).to_string();

        let run = prepare_cli_tool_run(
            "secret-scan:scan".to_string(),
            raw_input,
            Vec::new(),
            None,
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        let canonical_target = target.path().canonicalize().unwrap();

        assert_eq!(
            run.workspace.as_ref().map(|workspace| workspace.root()),
            Some(canonical_target.as_path())
        );
        assert_eq!(run.artifact_target, canonical_target);
        assert!(run.store.is_some());
    }

    #[test]
    fn session_target_override_establishes_the_cli_workspace() {
        let target = tempfile::tempdir().unwrap();
        let option = format!("target={}", target.path().display());

        let run = prepare_cli_tool_run(
            "secret-scan:scan".to_string(),
            "{}".to_string(),
            vec![option],
            None,
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        let canonical_target = target.path().canonicalize().unwrap();

        assert_eq!(run.artifact_target, canonical_target);
        assert!(run.workspace.is_some());
        assert!(run.store.is_some());
        assert!(target.path().join(".kuzushi/.gitignore").is_file());
    }

    #[test]
    fn raw_input_target_precedes_the_session_target_override() {
        let explicit = tempfile::tempdir().unwrap();
        let session = tempfile::tempdir().unwrap();
        let input = serde_json::json!({ "target": explicit.path() }).to_string();
        let option = format!("target={}", session.path().display());

        let run = prepare_cli_tool_run(
            "secret-scan:scan".to_string(),
            input,
            vec![option],
            None,
            None,
            Vec::new(),
            None,
        )
        .unwrap();

        let canonical_target = explicit.path().canonicalize().unwrap();
        assert_eq!(run.artifact_target, canonical_target);
        assert_eq!(
            run.input.value()["target"],
            canonical_target.display().to_string()
        );
    }

    #[test]
    fn prepare_rejection_persists_a_typed_blocked_call_and_terminal() {
        let target = tempfile::tempdir().unwrap();
        let error = reject_unknown_cli_option(target.path());
        assert!(error.to_string().contains("unknown"));

        let (run_id, read) = load_latest_preparation_rejection(target.path());
        assert_blocked_preparation_projection(&read);
        assert_eq!(
            kuzushi_core::load_run_summary(target.path(), &run_id)
                .unwrap()
                .status,
            "blocked"
        );
        let outcome = kuzushi_core::load_persisted_run_terminal_outcome(target.path(), &run_id)
            .expect("prepare rejection must have one agreeing terminal bundle");
        assert_eq!(
            outcome.status,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        );
        assert_eq!(outcome.result["status"], "blocked");
        let done: serde_json::Value = serde_json::from_slice(
            &std::fs::read(kuzushi_core::run_dir(target.path(), &run_id).join("done.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(done["status"], "blocked");
        assert_eq!(done["exitCode"], 2);
        assert_rejection_artifact_correlation(&read);
        assert_items_redact_raw_input(target.path(), &run_id);
    }

    fn reject_unknown_cli_option(target: &std::path::Path) -> anyhow::Error {
        prepare_cli_tool_run(
            "workspace:status".to_string(),
            serde_json::json!({"unknownOption": "raw-option-sentinel"}).to_string(),
            Vec::new(),
            None,
            Some(target.to_path_buf()),
            Vec::new(),
            None,
        )
        .err()
        .expect("unknown option should be rejected")
    }

    fn load_latest_preparation_rejection(
        target: &std::path::Path,
    ) -> (String, kuzushi_core::run_lifecycle::RunProjectionRead) {
        let entry = kuzushi_core::list_recent_run_summary_entries(target, 1)
            .unwrap()
            .pop()
            .unwrap();
        let read = kuzushi_core::run_lifecycle::load_run_projection(target, &entry.run_id).unwrap();
        (entry.run_id, read)
    }

    fn assert_blocked_preparation_projection(
        read: &kuzushi_core::run_lifecycle::RunProjectionRead,
    ) {
        assert_eq!(
            read.source,
            kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1
        );
        assert_eq!(read.projection.tasks.len(), 1);
        assert_eq!(read.projection.calls.len(), 1);
        let call = read.projection.calls.values().next().unwrap();
        assert_eq!(
            call.status,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        );
        assert_eq!(
            read.projection
                .terminal
                .as_ref()
                .map(|terminal| terminal.status),
            Some(kuzushi_core::run_lifecycle::RunItemStatus::Blocked)
        );
    }

    fn assert_rejection_artifact_correlation(
        read: &kuzushi_core::run_lifecycle::RunProjectionRead,
    ) {
        let call = read.projection.calls.values().next().unwrap();
        assert!(!read.projection.artifacts.is_empty());
        assert!(read
            .projection
            .artifacts
            .values()
            .all(|artifact| artifact.producing_item_id == call.item_id));
        assert_eq!(
            call.related_artifact_ids.len(),
            read.projection.artifacts.len()
        );
        assert_eq!(
            call.result_artifact
                .as_ref()
                .map(|artifact| artifact.path.as_str()),
            Some("result.json")
        );
    }

    fn assert_items_redact_raw_input(target: &std::path::Path, run_id: &str) {
        let items = std::fs::read_to_string(kuzushi_core::run_artifacts::run_artifact_path(
            target,
            run_id,
            "items.jsonl",
        ))
        .unwrap();
        assert!(!items.contains("raw-option-sentinel"));
    }

    #[test]
    fn conflicting_session_target_and_cwd_are_rejected() {
        let target = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let options = vec![
            format!("target={}", target.path().display()),
            format!("cwd={}", cwd.path().display()),
        ];

        let error = prepare_cli_tool_run(
            "secret-scan:scan".to_string(),
            "{}".to_string(),
            options,
            None,
            None,
            Vec::new(),
            None,
        )
        .err()
        .expect("conflicting invocation targets must fail")
        .to_string();

        assert!(error.contains("--option target"), "{error}");
        assert!(error.contains("conflicts with cwd"), "{error}");
    }

    #[test]
    fn an_undeclared_option_override_is_refused_like_an_unknown_input_key() {
        let workspace = tempfile::tempdir().unwrap();

        let error = prepare_cli_tool_run(
            "secret-scan:scan".to_string(),
            "{}".to_string(),
            vec!["definitelyNotAnOption=1".to_string()],
            None,
            Some(workspace.path().to_path_buf()),
            Vec::new(),
            None,
        )
        .err()
        .expect("an undeclared --option must fail")
        .to_string();

        assert!(error.contains("received unknown option"), "{error}");
        assert!(error.contains("definitelyNotAnOption"), "{error}");
    }

    #[test]
    fn string_target_remains_domain_input_with_a_separate_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let input = serde_json::json!({
            "target": "10.0.0.5",
            "chain": { "name": "probe", "plays": [] },
        })
        .to_string();

        let run = prepare_cli_tool_run(
            "offense:chain".to_string(),
            input,
            Vec::new(),
            None,
            Some(workspace.path().to_path_buf()),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(
            run.artifact_target,
            workspace.path().canonicalize().unwrap()
        );
        assert_eq!(run.input.value()["target"], "10.0.0.5");
    }

    #[test]
    fn cli_launch_keeps_path_like_hydrated_prompt_as_prepared_input() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("review.md"), "nested.md").unwrap();
        std::fs::write(target.path().join("nested.md"), "wrong second hydration").unwrap();

        let run = prepare_cli_tool_run(
            "triage:run".to_string(),
            serde_json::json!({
                "fingerprint": "receipt-test-finding",
                "TRIAGE_PROMPT": "review.md"
            })
            .to_string(),
            Vec::new(),
            None,
            Some(target.path().to_path_buf()),
            Vec::new(),
            None,
        )
        .unwrap();

        let prepared_prompt = run.input.value()["TRIAGE_PROMPT"].as_str().unwrap();
        assert!(prepared_prompt.starts_with(kuzushi_core::runtime::DEFAULT_TRIAGE_PROMPT));
        let record = decode_first_repo_record(prepared_prompt);
        assert_eq!(record.label, "review.md");
        assert_eq!(record.content, "nested.md");
        let ctx = kuzushi_core::ToolExecutionContext {
            config: &run.config,
            workspace: run.workspace.as_ref(),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let second_pass = run
            .registry
            .prepare_dispatch_input("triage:run", run.input.value().clone(), &ctx, None)
            .unwrap();
        assert_eq!(second_pass.value()["TRIAGE_PROMPT"], prepared_prompt);
    }

    #[test]
    fn string_target_does_not_impersonate_a_missing_workspace() {
        let error = prepare_cli_tool_run(
            "recon:nmap".to_string(),
            serde_json::json!({ "target": "192.0.2.10" }).to_string(),
            Vec::new(),
            None,
            None,
            Vec::new(),
            None,
        )
        .err()
        .expect("network target must not satisfy the workspace requirement")
        .to_string();

        assert!(
            error.contains("requires an explicit workspace target"),
            "{error}"
        );
        assert!(!error.contains("192.0.2.10"), "{error}");
    }

    #[test]
    fn dynamic_tool_requires_workspace_before_loading_its_descriptor() {
        let error = prepare_cli_tool_run(
            "dynamic-demo:scan".to_string(),
            serde_json::json!({"target": "."}).to_string(),
            Vec::new(),
            None,
            None,
            vec!["file:///tmp/dynamic-demo.mjs".to_string()],
            None,
        )
        .err()
        .expect("dynamic tools must not bootstrap trust from process cwd")
        .to_string();

        assert!(
            error.contains("require an explicit global --target"),
            "{error}"
        );
        assert!(error.contains("trusted-module policy"), "{error}");
    }

    #[test]
    fn start_record_persistence_errors_are_returned() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "run-start-collision";
        let input_path =
            kuzushi_core::run_artifacts::run_artifact_path(target.path(), run_id, "input.json");
        std::fs::create_dir_all(&input_path).unwrap();

        let error = record_cli_tool_run_started(
            target.path(),
            run_id,
            "context:build",
            &serde_json::json!({}),
            &V2Config::default(),
            Vec::new(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("input.json"), "{error}");
    }

    #[test]
    fn prepare_error_reports_a_secondary_persistence_failure() {
        let error = error_with_persistence(
            anyhow::anyhow!("input was invalid"),
            Err(anyhow::anyhow!("input.json is not a file")),
        )
        .to_string();

        assert!(error.contains("input was invalid"), "{error}");
        assert!(error.contains("run artifact persistence failed"), "{error}");
        assert!(error.contains("input.json is not a file"), "{error}");
    }
}
