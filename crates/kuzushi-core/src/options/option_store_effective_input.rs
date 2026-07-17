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
        self.effective_tool_input_with_stored_key_resolver(tool_name, explicit, |name| {
            include_stored_option(name).then(|| name.to_string())
        })
    }

    pub fn effective_tool_input_with_stored_key_resolver(
        &self,
        tool_name: &str,
        explicit: Value,
        mut canonical_stored_option: impl FnMut(&str) -> Option<String>,
    ) -> Result<Value> {
        if self.bindings.is_empty() {
            return Ok(explicit);
        }

        let mut merged = Map::new();
        self.merge_effective_stored_values_with_key_resolver(
            tool_name,
            &mut merged,
            &mut canonical_stored_option,
        );
        merge_explicit_input_with_key_resolver(
            tool_name,
            explicit,
            &mut merged,
            &mut canonical_stored_option,
        )?;
        Ok(Value::Object(merged))
    }

    pub fn effective_stored_values(&self, tool_name: &str) -> BTreeMap<String, Value> {
        let mut merged = Map::new();
        self.merge_effective_stored_values(tool_name, &mut merged);
        merged.into_iter().collect()
    }

    pub fn stored_values_for_scope(
        &self,
        scope: OptionScope,
        tool_name: &str,
    ) -> BTreeMap<String, Value> {
        let mut merged = BTreeMap::new();
        self.extend_scope_target(scope, &OptionTarget::All, &mut merged);
        if let Some((module_id, _)) = tool_name.split_once(':') {
            self.extend_scope_target(
                scope,
                &OptionTarget::Module(module_id.to_string()),
                &mut merged,
            );
        }
        self.extend_scope_target(
            scope,
            &OptionTarget::Tool(tool_name.to_string()),
            &mut merged,
        );
        merged
    }

    fn extend_scope_target(
        &self,
        scope: OptionScope,
        target: &OptionTarget,
        merged: &mut BTreeMap<String, Value>,
    ) {
        if let Some(values) = self.values_for(scope, target) {
            merged.extend(values.clone());
        }
    }

    pub fn effective_stored_value_scope(
        &self,
        tool_name: &str,
        option_name: &str,
    ) -> Option<OptionScope> {
        let module_id = tool_name.split_once(':').map(|(module, _)| module);
        let mut source = None;
        for scope in [
            OptionScope::Global,
            OptionScope::Workspace,
            OptionScope::Session,
        ] {
            source = self
                .target_value_scope(scope, &OptionTarget::All, option_name)
                .or(source);
            if let Some(module_id) = module_id {
                source = self
                    .target_value_scope(
                        scope,
                        &OptionTarget::Module(module_id.to_string()),
                        option_name,
                    )
                    .or(source);
            }
            source = self
                .target_value_scope(
                    scope,
                    &OptionTarget::Tool(tool_name.to_string()),
                    option_name,
                )
                .or(source);
        }
        source
    }

    fn target_value_scope(
        &self,
        scope: OptionScope,
        target: &OptionTarget,
        option_name: &str,
    ) -> Option<OptionScope> {
        self.values_for(scope, target)
            .is_some_and(|values| values.contains_key(option_name))
            .then_some(scope)
    }

    pub(crate) fn merge_effective_stored_values(
        &self,
        tool_name: &str,
        merged: &mut Map<String, Value>,
    ) {
        self.merge_effective_stored_values_with_key_resolver(tool_name, merged, &mut |name| {
            Some(name.to_string())
        });
    }

    fn merge_effective_stored_values_with_key_resolver(
        &self,
        tool_name: &str,
        merged: &mut Map<String, Value>,
        canonical_stored_option: &mut impl FnMut(&str) -> Option<String>,
    ) {
        let module_id = tool_name.split_once(':').map(|(module, _)| module);

        for scope in [
            OptionScope::Global,
            OptionScope::Workspace,
            OptionScope::Session,
        ] {
            self.merge_target_with_key_resolver(
                scope,
                &OptionTarget::All,
                merged,
                canonical_stored_option,
            );
            if let Some(module_id) = module_id {
                self.merge_target_with_key_resolver(
                    scope,
                    &OptionTarget::Module(module_id.to_string()),
                    merged,
                    canonical_stored_option,
                );
            }
            self.merge_target_with_key_resolver(
                scope,
                &OptionTarget::Tool(tool_name.to_string()),
                merged,
                canonical_stored_option,
            );
        }
    }

    fn merge_target_with_key_resolver(
        &self,
        scope: OptionScope,
        target: &OptionTarget,
        merged: &mut Map<String, Value>,
        canonical_stored_option: &mut impl FnMut(&str) -> Option<String>,
    ) {
        let Some(values) = self.values_for(scope, target) else {
            return;
        };
        let mut canonical = Map::new();
        for (name, value) in values {
            let Some(canonical_name) = canonical_stored_option(name) else {
                continue;
            };
            if name == &canonical_name || !canonical.contains_key(&canonical_name) {
                canonical.insert(canonical_name, value.clone());
            }
        }
        merged.extend(canonical);
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

fn merge_explicit_input_with_key_resolver(
    tool_name: &str,
    explicit: Value,
    merged: &mut Map<String, Value>,
    canonical_stored_option: &mut impl FnMut(&str) -> Option<String>,
) -> Result<()> {
    match explicit {
        Value::Null => {}
        Value::Object(object) => {
            let mut canonical = Map::new();
            for (name, value) in object {
                let canonical_name = canonical_stored_option(&name).unwrap_or_else(|| name.clone());
                if name == canonical_name || !canonical.contains_key(&canonical_name) {
                    canonical.insert(canonical_name, value);
                }
            }
            merged.extend(canonical);
        }
        other => {
            anyhow::bail!(
                "stored options for {tool_name} require a JSON object input, got {}",
                json_summary(&other)
            );
        }
    }
    Ok(())
}
