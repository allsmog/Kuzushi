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
}

pub fn load_config_for_target(target: Option<&Path>) -> Result<V2Config> {
    load_config(ConfigPaths::from_target(target)?)
}

pub fn load_config(paths: ConfigPaths) -> Result<V2Config> {
    let mut config = V2Config::default();

    let global_path = paths.global_config_path();
    if global_path.exists() {
        merge_file(&mut config, &global_path)?;
    }

    if let Some(project_path) = paths.project_config_path() {
        if project_path.exists() {
            merge_file(&mut config, &project_path)?;
        }
    }

    apply_env_overrides(&mut config);
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

pub(crate) fn merge_file(config: &mut V2Config, path: &Path) -> Result<()> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("Could not read {}", path.display()))?;
    let patch: PartialConfig =
        toml::from_str(&raw).with_context(|| format!("Could not parse {}", path.display()))?;
    merge_config(config, patch);
    Ok(())
}

pub(crate) fn merge_config(config: &mut V2Config, patch: PartialConfig) {
    if let Some(model) = patch.model {
        config.model = model;
    }

    if let Some(runtime) = patch.runtime {
        if let Some(kind) = runtime.kind {
            config.runtime.kind = kind;
        }
        if let Some(api_key_env) = runtime.api_key_env {
            config.runtime.api_key_env = api_key_env;
        }
        if let Some(base_url) = runtime.base_url {
            config.runtime.base_url = base_url;
        }
        if let Some(agent_bridge_command) = runtime.agent_bridge_command {
            config.runtime.agent_bridge_command = agent_bridge_command;
        }
        if let Some(thinking_level) = runtime.thinking_level {
            config.runtime.thinking_level = thinking_level;
        }
        if let Some(anthropic_oauth) = runtime.anthropic_oauth {
            config.runtime.anthropic_oauth = anthropic_oauth;
        }
    }

    if let Some(operator) = patch.operator {
        if let Some(session_budget_usd) = operator.session_budget_usd {
            config.operator.session_budget_usd = session_budget_usd;
        }
        if let Some(spend_hard_ceiling_usd) = operator.spend_hard_ceiling_usd {
            config.operator.spend_hard_ceiling_usd = spend_hard_ceiling_usd;
        }
        if let Some(trusted_workflow_auto_accept) = operator.trusted_workflow_auto_accept {
            config.operator.trusted_workflow_auto_accept = trusted_workflow_auto_accept;
        }
    }
}
