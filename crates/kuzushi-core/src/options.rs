use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionScope {
    Global,
    Workspace,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "kebab-case")]
pub enum OptionTarget {
    All,
    Module(String),
    Tool(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OptionBinding {
    pub scope: OptionScope,
    pub target: OptionTarget,
}

impl OptionBinding {
    pub fn new(scope: OptionScope, target: OptionTarget) -> Self {
        Self { scope, target }
    }
}

impl Serialize for OptionBinding {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.storage_key())
    }
}

impl<'de> Deserialize<'de> for OptionBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_storage_key(&raw).map_err(serde::de::Error::custom)
    }
}

impl OptionBinding {
    fn storage_key(&self) -> String {
        let scope = match self.scope {
            OptionScope::Global => "global",
            OptionScope::Workspace => "workspace",
            OptionScope::Session => "session",
        };
        let target = match &self.target {
            OptionTarget::All => "all".to_string(),
            OptionTarget::Module(module) => format!("module/{module}"),
            OptionTarget::Tool(tool) => format!("tool/{tool}"),
        };
        format!("{scope}/{target}")
    }

    fn from_storage_key(raw: &str) -> Result<Self> {
        let mut parts = raw.splitn(3, '/');
        let scope = match parts.next().unwrap_or_default() {
            "global" => OptionScope::Global,
            "workspace" => OptionScope::Workspace,
            "session" => OptionScope::Session,
            other => anyhow::bail!("unknown option scope {other:?}"),
        };
        let target_kind = parts
            .next()
            .context("option binding key is missing target kind")?;
        let target = match target_kind {
            "all" => OptionTarget::All,
            "module" => OptionTarget::Module(
                parts
                    .next()
                    .filter(|id| !id.trim().is_empty())
                    .context("module option binding key is missing module id")?
                    .to_string(),
            ),
            "tool" => OptionTarget::Tool(
                parts
                    .next()
                    .filter(|id| !id.trim().is_empty())
                    .context("tool option binding key is missing tool id")?
                    .to_string(),
            ),
            other => anyhow::bail!("unknown option target kind {other:?}"),
        };
        Ok(Self { scope, target })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ToolOptionStore {
    bindings: BTreeMap<OptionBinding, BTreeMap<String, Value>>,
}

impl ToolOptionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Could not read option store {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("Could not parse option store {}", path.display()))
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Could not create option store directory {}",
                    parent.display()
                )
            })?;
        }
        let body =
            serde_json::to_string_pretty(self).context("Could not serialize option store")?;
        fs::write(path, body)
            .with_context(|| format!("Could not write option store {}", path.display()))
    }

    pub fn set_value(
        &mut self,
        scope: OptionScope,
        target: OptionTarget,
        name: impl Into<String>,
        value: Value,
    ) {
        self.bindings
            .entry(OptionBinding::new(scope, target))
            .or_default()
            .insert(name.into(), value);
    }

    pub fn unset_value(&mut self, scope: OptionScope, target: &OptionTarget, name: &str) -> bool {
        let binding = OptionBinding::new(scope, target.clone());
        let Some(values) = self.bindings.get_mut(&binding) else {
            return false;
        };
        let removed = values.remove(name).is_some();
        if values.is_empty() {
            self.bindings.remove(&binding);
        }
        removed
    }

    pub fn values_for(
        &self,
        scope: OptionScope,
        target: &OptionTarget,
    ) -> Option<&BTreeMap<String, Value>> {
        self.bindings
            .get(&OptionBinding::new(scope, target.clone()))
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn effective_tool_input(&self, tool_name: &str, explicit: Value) -> Result<Value> {
        if self.bindings.is_empty() {
            return Ok(explicit);
        }

        let mut merged = Map::new();
        self.merge_effective_stored_values(tool_name, &mut merged);

        match explicit {
            Value::Null => {}
            Value::Object(object) => {
                for (name, value) in object {
                    merged.insert(name, value);
                }
            }
            other => {
                anyhow::bail!(
                    "stored options for {tool_name} require a JSON object input, got {}",
                    json_summary(&other)
                );
            }
        }

        Ok(Value::Object(merged))
    }

    pub fn effective_stored_values(&self, tool_name: &str) -> BTreeMap<String, Value> {
        let mut merged = Map::new();
        self.merge_effective_stored_values(tool_name, &mut merged);
        merged.into_iter().collect()
    }

    fn merge_effective_stored_values(&self, tool_name: &str, merged: &mut Map<String, Value>) {
        let module_id = tool_name.split_once(':').map(|(module, _)| module);

        for scope in [
            OptionScope::Global,
            OptionScope::Workspace,
            OptionScope::Session,
        ] {
            self.merge_target(scope, &OptionTarget::All, merged);
            if let Some(module_id) = module_id {
                self.merge_target(scope, &OptionTarget::Module(module_id.to_string()), merged);
            }
            self.merge_target(scope, &OptionTarget::Tool(tool_name.to_string()), merged);
        }
    }

    fn merge_target(
        &self,
        scope: OptionScope,
        target: &OptionTarget,
        merged: &mut Map<String, Value>,
    ) {
        if let Some(values) = self.values_for(scope, target) {
            for (name, value) in values {
                merged.insert(name.clone(), value.clone());
            }
        }
    }
}

fn json_summary(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<json>".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merges_options_with_deterministic_scope_and_specificity_precedence() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "limit",
            json!("global-all"),
        );
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("semgrep:scan".to_string()),
            "limit",
            json!("global-tool"),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("semgrep:scan".to_string()),
            "limit",
            json!("workspace-tool"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Module("semgrep".to_string()),
            "limit",
            json!("session-module"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("semgrep:scan".to_string()),
            "config",
            json!("p/ci"),
        );

        let input = store
            .effective_tool_input("semgrep:scan", json!({"limit": "explicit"}))
            .unwrap();

        assert_eq!(input["limit"], json!("explicit"));
        assert_eq!(input["config"], json!("p/ci"));
    }

    #[test]
    fn applies_session_values_over_persistent_values_without_explicit_input() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Module("sast".to_string()),
            "triage",
            json!(true),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(false),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Module("sast".to_string()),
            "triage",
            json!(true),
        );

        let input = store.effective_tool_input("sast:scan", json!({})).unwrap();

        assert_eq!(input["triage"], json!(true));
    }

    #[test]
    fn persistent_store_writes_only_when_save_is_explicit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".kuzushi/v2/options.json");
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(true),
        );

        assert!(!path.exists());
        store.save_to_path(&path).unwrap();
        assert!(path.exists());

        let loaded = ToolOptionStore::load_from_path(&path).unwrap();
        assert_eq!(loaded, store);
    }

    #[test]
    fn rejects_non_object_explicit_input_when_stored_options_would_merge() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(true),
        );

        let error = store
            .effective_tool_input("sast:scan", json!(["not", "object"]))
            .unwrap_err();
        assert!(error.to_string().contains("require a JSON object input"));
    }
}
