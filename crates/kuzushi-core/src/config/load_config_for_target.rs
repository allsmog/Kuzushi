use super::*;

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PartialRuntimeConfig {
    pub(crate) kind: Option<RuntimeKind>,
    pub(crate) api_key_env: Option<String>,
    pub(crate) base_url: Option<Option<String>>,
    pub(crate) agent_bridge_command: Option<Option<Vec<String>>>,
    pub(crate) thinking_level: Option<Option<String>>,
    pub(crate) anthropic_oauth: Option<Option<AnthropicOauthConfig>>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PartialOperatorConfig {
    pub(crate) session_budget_usd: Option<Option<f64>>,
    pub(crate) spend_hard_ceiling_usd: Option<Option<f64>>,
    pub(crate) trusted_workflow_auto_accept: Option<bool>,
    pub(crate) trusted_modules: Option<Vec<String>>,
}

pub fn load_config_for_target(target: Option<&Path>) -> Result<V2Config> {
    load_config(ConfigPaths::from_target(target)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    /// Operator-owned config under `$HOME/.kuzushi/v2/`. Trusted.
    Global,
    /// Config under `<target>/.kuzushi/v2/`. Untrusted: a scanned repository
    /// can include this file, so `[runtime]` and `[operator]` fields must
    /// never be honored from this source.
    Project,
}

pub fn load_config(paths: ConfigPaths) -> Result<V2Config> {
    let mut config = V2Config::default();

    merge_existing_file(&mut config, paths.global_config_path(), ConfigSource::Global)?;
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

pub(crate) fn write_config_body(path: &Path, body: String) -> Result<()> {
    fs::write(path, body).with_context(|| format!("Could not write {}", path.display()))
}

fn merge_project_file(config: &mut V2Config, path: Option<PathBuf>) -> Result<()> {
    match path {
        Some(path) => merge_existing_file(config, path, ConfigSource::Project),
        None => Ok(()),
    }
}

fn merge_existing_file(config: &mut V2Config, path: PathBuf, source: ConfigSource) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    merge_file(config, &path, source)
}

pub(crate) fn merge_file(
    config: &mut V2Config,
    path: &Path,
    source: ConfigSource,
) -> Result<()> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("Could not read {}", path.display()))?;
    let patch: PartialConfig =
        toml::from_str(&raw).with_context(|| format!("Could not parse {}", path.display()))?;
    reject_untrusted_runtime_overrides(path, &patch, source)?;
    merge_config(config, patch);
    Ok(())
}

/// A target repository's `.kuzushi/v2/config.toml` is loaded as part of the
/// effective configuration, but it must not be able to redirect the agent
/// bridge, API endpoint, credential env var, OAuth config, or operator
/// safety knobs — those are operator decisions that must come from the
/// global config under `$HOME/.kuzushi/v2/`. Without this gate a malicious
/// target repo could swap `agent_bridge_command` for an exfil binary that
/// receives the operator's API key over stdin.
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
         come from the global config at $HOME/.kuzushi/v2/config.toml — a \
         target repository must not be able to redirect credentials or \
         process execution. Move these settings to the global config, or \
         remove them from the project file.",
        path.display(),
        forbidden.join(", "),
    );
}

fn forbidden_project_fields(patch: &PartialConfig) -> Vec<&'static str> {
    let mut fields = forbidden_runtime_fields(patch.runtime.as_ref());
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
            "runtime.agent_bridge_command",
            runtime.agent_bridge_command.is_some(),
        ),
        ("runtime.thinking_level", runtime.thinking_level.is_some()),
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
        ("operator.trusted_modules", operator.trusted_modules.is_some()),
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
}

fn merge_runtime_config(config: &mut RuntimeConfig, patch: PartialRuntimeConfig) {
    apply_patch_field(&mut config.kind, patch.kind);
    apply_patch_field(&mut config.api_key_env, patch.api_key_env);
    apply_patch_field(&mut config.base_url, patch.base_url);
    apply_patch_field(&mut config.agent_bridge_command, patch.agent_bridge_command);
    apply_patch_field(&mut config.thinking_level, patch.thinking_level);
    apply_patch_field(&mut config.anthropic_oauth, patch.anthropic_oauth);
}

fn merge_operator_config(config: &mut OperatorConfig, patch: PartialOperatorConfig) {
    apply_patch_field(
        &mut config.session_budget_usd,
        patch.session_budget_usd,
    );
    apply_patch_field(
        &mut config.spend_hard_ceiling_usd,
        patch.spend_hard_ceiling_usd,
    );
    apply_patch_field(
        &mut config.trusted_workflow_auto_accept,
        patch.trusted_workflow_auto_accept,
    );
    apply_patch_field(&mut config.trusted_modules, patch.trusted_modules);
}

fn apply_patch_field<T>(target: &mut T, patch: Option<T>) {
    if let Some(value) = patch {
        *target = value;
    }
}
