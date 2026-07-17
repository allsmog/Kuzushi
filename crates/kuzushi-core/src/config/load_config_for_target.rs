use super::config_file_io::{read_optional_config, write_config_body};
use super::*;

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PartialRuntimeConfig {
    pub(crate) kind: Option<RuntimeKind>,
    pub(crate) api_key_env: Option<String>,
    pub(crate) base_url: Option<Option<String>>,
    pub(crate) langgraph_bridge_command: Option<Option<Vec<String>>>,
    pub(crate) thinking_level: Option<Option<String>>,
    pub(crate) worker_watchdog_timeout_ms: Option<Option<u64>>,
    pub(crate) anthropic_oauth: Option<Option<AnthropicOauthConfig>>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PartialOperatorConfig {
    pub(crate) session_budget_usd: Option<Option<f64>>,
    pub(crate) spend_hard_ceiling_usd: Option<Option<f64>>,
    pub(crate) trusted_workflow_auto_accept: Option<bool>,
    pub(crate) trusted_modules: Option<Vec<String>>,
    pub(crate) signature_keys: Option<Vec<crate::worker_protocol::SignatureTrustKey>>,
    pub(crate) mcp_mounts: Option<Vec<McpMountConfig>>,
    pub(crate) fuzz_executors: Option<Vec<FuzzExecutorConfig>>,
    pub(crate) keybindings: Option<Vec<KeybindingOverrideConfig>>,
    pub(crate) session_retention_days: Option<u64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub(crate) struct PartialGuidedPhaseConfig {
    pub(crate) stop_after: Option<Option<GuidedPhase>>,
    pub(crate) map: Option<PartialPhaseTemplateConfig>,
    #[serde(alias = "hunt")]
    pub(crate) scan: Option<PartialPhaseTemplateConfig>,
    pub(crate) review: Option<PartialPhaseTemplateConfig>,
    #[serde(alias = "confirm")]
    pub(crate) prove: Option<PartialPhaseTemplateConfig>,
    pub(crate) fix: Option<PartialPhaseTemplateConfig>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub(crate) struct PartialPhaseTemplateConfig {
    pub(crate) budget_usd: Option<Option<f64>>,
    pub(crate) concurrency: Option<Option<usize>>,
    pub(crate) strategy_cap: Option<Option<usize>>,
    pub(crate) confirmation_depth: Option<Option<String>>,
    pub(crate) prompt_variant: Option<Option<String>>,
}

pub fn load_config_for_target(target: Option<&Path>) -> Result<V2Config> {
    load_config(ConfigPaths::from_target(target)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    /// Operator-owned config under `$HOME/.kuzushi/v3/`. Trusted.
    Global,
    /// Config under `<target>/.kuzushi/v3/`. Untrusted: a scanned repository
    /// can include this file, so model/runtime/operator fields must never be
    /// honored from this source.
    Project,
}

pub fn load_config(paths: ConfigPaths) -> Result<V2Config> {
    let mut config = V2Config::default();

    merge_existing_file(
        &mut config,
        paths.global_config_path(),
        ConfigSource::Global,
    )?;
    merge_project_file(&mut config, paths.project_config_path())?;
    apply_env_overrides(&mut config);
    normalize_config(&mut config)?;
    validate_config(&config)?;
    Ok(config)
}

pub fn load_anthropic_oauth_config(paths: &ConfigPaths) -> Result<Option<AnthropicOauthConfig>> {
    Ok(load_config(paths.clone())?.runtime.anthropic_oauth)
}

pub fn write_default_config(path: &Path) -> Result<()> {
    create_config_parent(path)?;
    write_config_body(path, default_config_body()?)
}

pub fn persist_global_model_selection(
    model: &str,
    thinking_level: Option<&str>,
) -> Result<PathBuf> {
    let paths = ConfigPaths::from_target(None)?;
    let path = paths.global_config_path();
    let mut config = global_config_for_write(&path)?;
    config.model = Some(model.to_string());
    config.runtime.thinking_level = thinking_level.map(str::to_string);
    create_config_parent(&path)?;
    write_config_body(
        &path,
        toml::to_string_pretty(&config).context("Could not serialize config")?,
    )?;
    Ok(path)
}

fn global_config_for_write(path: &Path) -> Result<V2Config> {
    let Some(raw) = read_optional_config(path)? else {
        return Ok(V2Config::default());
    };
    toml::from_str(&raw).with_context(|| format!("Could not parse {}", path.display()))
}

pub(crate) fn create_config_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create config directory {}", parent.display()))?;
    }
    Ok(())
}

pub(crate) fn default_config_body() -> Result<String> {
    let runtime = toml::to_string_pretty(&V2Config::default())
        .context("Could not serialize default config")?;
    Ok(format!(
        "# Kuzushi config. Set an explicit model before LLM triage.\n# model = \"openai:<model>\"\n\n{runtime}"
    ))
}

fn merge_project_file(config: &mut V2Config, path: Option<PathBuf>) -> Result<()> {
    match path {
        Some(path) => merge_existing_file(config, path, ConfigSource::Project),
        None => Ok(()),
    }
}

fn merge_existing_file(config: &mut V2Config, path: PathBuf, source: ConfigSource) -> Result<()> {
    let Some(raw) = read_optional_config(&path)? else {
        return Ok(());
    };
    merge_config_body(config, &path, source, &raw)
}

fn merge_config_body(
    config: &mut V2Config,
    path: &Path,
    source: ConfigSource,
    raw: &str,
) -> Result<()> {
    let patch: PartialConfig =
        toml::from_str(raw).with_context(|| format!("Could not parse {}", path.display()))?;
    warn_deprecated_phase_config(path, raw);
    reject_untrusted_runtime_overrides(path, &patch, source)?;
    merge_config(config, patch);
    Ok(())
}

fn warn_deprecated_phase_config(path: &Path, raw: &str) {
    let Ok(value) = toml::from_str::<toml::Value>(raw) else {
        return;
    };
    let Some(phases) = value.get("phases").and_then(toml::Value::as_table) else {
        return;
    };
    for (old, replacement) in [("hunt", "scan"), ("confirm", "prove")] {
        if phases.contains_key(old)
            || phases
                .get("stop_after")
                .and_then(toml::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(old))
        {
            eprintln!(
                "warning: {} uses deprecated phases.{old}/{old}; use phases.{replacement}/{replacement}",
                path.display()
            );
        }
    }
}

/// A target repository's `.kuzushi/v3/config.toml` is loaded as part of the
/// effective configuration, but it must not be able to redirect model choice,
/// the agent bridge, API endpoint, credential env var, OAuth config, or
/// operator safety knobs — those are operator decisions that must come from
/// the global config under `$HOME/.kuzushi/v3/`. Without this gate a malicious
/// target repo could steer spend/model safety or swap `langgraph_bridge_command`
/// for an exfil binary that receives the operator's API key over stdin.
fn reject_untrusted_runtime_overrides(
    path: &Path,
    patch: &PartialConfig,
    source: ConfigSource,
) -> Result<()> {
    if source != ConfigSource::Project {
        return Ok(());
    }
    let forbidden = forbidden_project_fields(patch);
    if forbidden.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "project config at {} sets operator-only fields ({}). These can only \
         come from the global config at $HOME/.kuzushi/v3/config.toml — a \
         target repository must not be able to redirect credentials or \
         process execution. Move these settings to the global config, or \
         remove them from the project file.",
        path.display(),
        forbidden.join(", "),
    );
}

fn forbidden_project_fields(patch: &PartialConfig) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if patch.model.is_some() {
        fields.push("model");
    }
    fields.extend(forbidden_runtime_fields(patch.runtime.as_ref()));
    fields.extend(forbidden_operator_fields(patch.operator.as_ref()));
    fields
}

fn forbidden_runtime_fields(runtime: Option<&PartialRuntimeConfig>) -> Vec<&'static str> {
    let Some(runtime) = runtime else {
        return Vec::new();
    };
    [
        ("runtime.kind", runtime.kind.is_some()),
        ("runtime.api_key_env", runtime.api_key_env.is_some()),
        ("runtime.base_url", runtime.base_url.is_some()),
        (
            "runtime.langgraph_bridge_command",
            runtime.langgraph_bridge_command.is_some(),
        ),
        ("runtime.thinking_level", runtime.thinking_level.is_some()),
        (
            "runtime.worker_watchdog_timeout_ms",
            runtime.worker_watchdog_timeout_ms.is_some(),
        ),
        ("runtime.anthropic_oauth", runtime.anthropic_oauth.is_some()),
    ]
    .into_iter()
    .filter_map(|(field, present)| present.then_some(field))
    .collect()
}

fn forbidden_operator_fields(operator: Option<&PartialOperatorConfig>) -> Vec<&'static str> {
    let Some(operator) = operator else {
        return Vec::new();
    };
    [
        (
            "operator.session_budget_usd",
            operator.session_budget_usd.is_some(),
        ),
        (
            "operator.spend_hard_ceiling_usd",
            operator.spend_hard_ceiling_usd.is_some(),
        ),
        (
            "operator.trusted_workflow_auto_accept",
            operator.trusted_workflow_auto_accept.is_some(),
        ),
        (
            "operator.trusted_modules",
            operator.trusted_modules.is_some(),
        ),
        ("operator.signature_keys", operator.signature_keys.is_some()),
        ("operator.mcp_mounts", operator.mcp_mounts.is_some()),
        ("operator.fuzz_executors", operator.fuzz_executors.is_some()),
        ("operator.keybindings", operator.keybindings.is_some()),
        (
            "operator.session_retention_days",
            operator.session_retention_days.is_some(),
        ),
    ]
    .into_iter()
    .filter_map(|(field, present)| present.then_some(field))
    .collect()
}

pub(crate) fn merge_config(config: &mut V2Config, patch: PartialConfig) {
    apply_patch_field(&mut config.model, patch.model);
    if let Some(runtime) = patch.runtime {
        merge_runtime_config(&mut config.runtime, runtime);
    }
    if let Some(operator) = patch.operator {
        merge_operator_config(&mut config.operator, operator);
    }
    if let Some(phases) = patch.phases {
        merge_guided_phase_config(&mut config.phases, phases);
    }
}

fn merge_runtime_config(config: &mut RuntimeConfig, patch: PartialRuntimeConfig) {
    apply_patch_field(&mut config.kind, patch.kind);
    apply_patch_field(&mut config.api_key_env, patch.api_key_env);
    apply_patch_field(&mut config.base_url, patch.base_url);
    apply_patch_field(
        &mut config.langgraph_bridge_command,
        patch.langgraph_bridge_command,
    );
    apply_patch_field(&mut config.thinking_level, patch.thinking_level);
    apply_patch_field(
        &mut config.worker_watchdog_timeout_ms,
        patch.worker_watchdog_timeout_ms,
    );
    apply_patch_field(&mut config.anthropic_oauth, patch.anthropic_oauth);
}

fn merge_operator_config(config: &mut OperatorConfig, patch: PartialOperatorConfig) {
    apply_patch_field(&mut config.session_budget_usd, patch.session_budget_usd);
    apply_patch_field(
        &mut config.spend_hard_ceiling_usd,
        patch.spend_hard_ceiling_usd,
    );
    apply_patch_field(
        &mut config.trusted_workflow_auto_accept,
        patch.trusted_workflow_auto_accept,
    );
    apply_patch_field(&mut config.trusted_modules, patch.trusted_modules);
    apply_patch_field(&mut config.signature_keys, patch.signature_keys);
    apply_patch_field(&mut config.mcp_mounts, patch.mcp_mounts);
    apply_patch_field(&mut config.fuzz_executors, patch.fuzz_executors);
    apply_patch_field(&mut config.keybindings, patch.keybindings);
    apply_patch_field(
        &mut config.session_retention_days,
        patch.session_retention_days,
    );
}

fn merge_guided_phase_config(config: &mut GuidedPhaseConfig, patch: PartialGuidedPhaseConfig) {
    apply_patch_field(&mut config.stop_after, patch.stop_after);
    merge_phase_template_config(&mut config.map, patch.map);
    merge_phase_template_config(&mut config.scan, patch.scan);
    merge_phase_template_config(&mut config.review, patch.review);
    merge_phase_template_config(&mut config.prove, patch.prove);
    merge_phase_template_config(&mut config.fix, patch.fix);
}

fn merge_phase_template_config(
    config: &mut PhaseTemplateConfig,
    patch: Option<PartialPhaseTemplateConfig>,
) {
    let Some(patch) = patch else {
        return;
    };
    apply_patch_field(&mut config.budget_usd, patch.budget_usd);
    apply_patch_field(&mut config.concurrency, patch.concurrency);
    apply_patch_field(&mut config.strategy_cap, patch.strategy_cap);
    apply_patch_field(&mut config.confirmation_depth, patch.confirmation_depth);
    apply_patch_field(&mut config.prompt_variant, patch.prompt_variant);
}

fn apply_patch_field<T>(target: &mut T, patch: Option<T>) {
    if let Some(value) = patch {
        *target = value;
    }
}
