use super::config_file_io::read_optional_config;
use super::ConfigPaths;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValueSource {
    OperatorConfig(PathBuf),
    TargetConfig(PathBuf),
    Environment(String),
}

impl ConfigValueSource {
    pub fn label(&self) -> String {
        match self {
            Self::OperatorConfig(path) => format!("operator config {}", path.display()),
            Self::TargetConfig(path) => format!("target config {}", path.display()),
            Self::Environment(name) => format!("environment {name}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigSourceInventory {
    sources: BTreeMap<String, ConfigValueSource>,
}

impl ConfigSourceInventory {
    pub fn inspect(paths: &ConfigPaths) -> Result<Self> {
        let mut inventory = Self::default();
        inventory.record_file(
            &paths.global_config_path(),
            ConfigValueSource::OperatorConfig(paths.global_config_path()),
        )?;
        if let Some(path) = paths.project_config_path() {
            inventory.record_file(&path, ConfigValueSource::TargetConfig(path.clone()))?;
        }
        inventory.record_environment();
        Ok(inventory)
    }

    pub fn source_of(&self, setting: &str) -> Option<&ConfigValueSource> {
        self.sources.get(setting)
    }

    fn record_file(&mut self, path: &Path, source: ConfigValueSource) -> Result<()> {
        let Some(raw) = read_optional_config(path)? else {
            return Ok(());
        };
        let value: toml::Value = toml::from_str(&raw)
            .with_context(|| format!("Could not inspect configuration sources in {}", path.display()))?;
        record_value_sources(&mut self.sources, "", &value, &source);
        Ok(())
    }

    fn record_environment(&mut self) {
        for (setting, names) in ENVIRONMENT_SETTING_SOURCES {
            if let Some(name) = names
                .iter()
                .find(|name| std::env::var_os(name).is_some())
            {
                self.sources.insert(
                    (*setting).to_string(),
                    ConfigValueSource::Environment((*name).to_string()),
                );
            }
        }
    }
}

fn record_value_sources(
    output: &mut BTreeMap<String, ConfigValueSource>,
    prefix: &str,
    value: &toml::Value,
    source: &ConfigValueSource,
) {
    let Some(table) = value.as_table() else {
        if !prefix.is_empty() {
            output.insert(canonical_setting_path(prefix), source.clone());
        }
        return;
    };
    for (name, child) in table {
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        record_value_sources(output, &path, child, source);
    }
}

fn canonical_setting_path(path: &str) -> String {
    if let Some(suffix) = path.strip_prefix("phases.hunt") {
        return format!("phases.scan{suffix}");
    }
    if let Some(suffix) = path.strip_prefix("phases.confirm") {
        return format!("phases.prove{suffix}");
    }
    path.to_string()
}

const ENVIRONMENT_SETTING_SOURCES: &[(&str, &[&str])] = &[
    ("model", &["KUZUSHI_MODEL", "KUZUSHI_V2_MODEL"]),
    (
        "runtime.api_key_env",
        &["KUZUSHI_API_KEY_ENV", "KUZUSHI_V2_API_KEY_ENV"],
    ),
    (
        "runtime.base_url",
        &["KUZUSHI_BASE_URL", "KUZUSHI_V2_BASE_URL"],
    ),
    (
        "runtime.langgraph_bridge_command",
        &["KUZUSHI_LANGGRAPH_BRIDGE"],
    ),
    (
        "runtime.anthropic_oauth",
        &[
            "KUZUSHI_ANTHROPIC_OAUTH",
            "KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS",
        ],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_target_values_override_operator_sources_and_aliases_are_canonical() {
        let root = tempfile::tempdir().unwrap();
        let operator = root.path().join("operator");
        let target = root.path().join("target");
        std::fs::create_dir_all(operator.join(".kuzushi/v3")).unwrap();
        std::fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        std::fs::write(
            operator.join(".kuzushi/v3/config.toml"),
            "[phases]\nstop_after='scan'\n[phases.scan]\nconcurrency=2\n",
        )
        .unwrap();
        std::fs::write(
            target.join(".kuzushi/v3/config.toml"),
            "[phases.hunt]\nconcurrency=3\n",
        )
        .unwrap();
        let paths = ConfigPaths {
            home_dir: operator.clone(),
            target_dir: Some(target.clone()),
        };

        let sources = ConfigSourceInventory::inspect(&paths).unwrap();

        assert!(matches!(
            sources.source_of("phases.stop_after"),
            Some(ConfigValueSource::OperatorConfig(_))
        ));
        assert_eq!(
            sources
                .source_of("phases.scan.concurrency")
                .map(ConfigValueSource::label),
            Some(format!(
                "target config {}",
                target.join(".kuzushi/v3/config.toml").display()
            ))
        );
    }
}
