use super::{OptionBinding, OptionScope, OptionTarget, ToolOptionStore};
use serde_json::Value;
use std::collections::BTreeMap;

impl ToolOptionStore {
    /// Every stored option with its exact scope and target. Presentation
    /// layers use this to explain effective defaults without reaching into
    /// the persistence representation.
    pub fn stored_values(&self) -> Vec<(OptionBinding, String, serde_json::Value)> {
        self.bindings
            .iter()
            .flat_map(|(binding, values)| {
                values.iter().map(|(name, value)| {
                    (binding.clone(), name.clone(), value.clone())
                })
            })
            .collect()
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

    pub fn value_count(&self) -> usize {
        self.bindings.values().map(BTreeMap::len).sum()
    }
}
