use super::prelude::*;
use super::*;

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

    pub(crate) fn merge_effective_stored_values(
        &self,
        tool_name: &str,
        merged: &mut Map<String, Value>,
    ) {
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

    pub(crate) fn merge_target(
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
