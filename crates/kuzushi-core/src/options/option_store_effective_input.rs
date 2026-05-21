use super::{json_summary, OptionScope, OptionTarget, ToolOptionStore};
use anyhow::Result;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

impl ToolOptionStore {
    pub fn effective_tool_input(&self, tool_name: &str, explicit: Value) -> Result<Value> {
        if self.bindings.is_empty() {
            return Ok(explicit);
        }

        let mut merged = Map::new();
        self.merge_effective_stored_values(tool_name, &mut merged);
        merge_explicit_input(tool_name, explicit, &mut merged)?;
        Ok(Value::Object(merged))
    }

    pub fn effective_tool_input_with_stored_filter(
        &self,
        tool_name: &str,
        explicit: Value,
        mut include_stored_option: impl FnMut(&str) -> bool,
    ) -> Result<Value> {
        if self.bindings.is_empty() {
            return Ok(explicit);
        }

        let mut merged = Map::new();
        self.merge_effective_stored_values_with_filter(
            tool_name,
            &mut merged,
            &mut include_stored_option,
        );
        merge_explicit_input(tool_name, explicit, &mut merged)?;
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
        self.merge_effective_stored_values_with_filter(tool_name, merged, &mut |_| true);
    }

    fn merge_effective_stored_values_with_filter(
        &self,
        tool_name: &str,
        merged: &mut Map<String, Value>,
        include_stored_option: &mut impl FnMut(&str) -> bool,
    ) {
        let module_id = tool_name.split_once(':').map(|(module, _)| module);

        for scope in [
            OptionScope::Global,
            OptionScope::Workspace,
            OptionScope::Session,
        ] {
            self.merge_target_with_filter(scope, &OptionTarget::All, merged, include_stored_option);
            if let Some(module_id) = module_id {
                self.merge_target_with_filter(
                    scope,
                    &OptionTarget::Module(module_id.to_string()),
                    merged,
                    include_stored_option,
                );
            }
            self.merge_target_with_filter(
                scope,
                &OptionTarget::Tool(tool_name.to_string()),
                merged,
                include_stored_option,
            );
        }
    }

    fn merge_target_with_filter(
        &self,
        scope: OptionScope,
        target: &OptionTarget,
        merged: &mut Map<String, Value>,
        include_stored_option: &mut impl FnMut(&str) -> bool,
    ) {
        if let Some(values) = self.values_for(scope, target) {
            for (name, value) in values {
                if include_stored_option(name) {
                    merged.insert(name.clone(), value.clone());
                }
            }
        }
    }
}

fn merge_explicit_input(
    tool_name: &str,
    explicit: Value,
    merged: &mut Map<String, Value>,
) -> Result<()> {
    match explicit {
        Value::Null => {}
        Value::Object(object) => merged.extend(object),
        other => {
            anyhow::bail!(
                "stored options for {tool_name} require a JSON object input, got {}",
                json_summary(&other)
            );
        }
    }
    Ok(())
}
