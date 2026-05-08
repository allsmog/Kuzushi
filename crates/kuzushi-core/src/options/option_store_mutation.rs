use super::{OptionBinding, OptionScope, OptionTarget, ToolOptionStore};
use serde_json::Value;
use std::collections::BTreeMap;

impl ToolOptionStore {
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
}
