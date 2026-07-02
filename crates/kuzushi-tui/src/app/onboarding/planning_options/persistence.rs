use crate::app::{format_option_value, PlanningTaskId};
use crate::ShellApp;
use kuzushi_core::modules::OptionSpec;
use kuzushi_core::{OptionScope, OptionTarget};
use serde_json::Value;

impl ShellApp {
    pub(crate) fn persist_selected_planning_option_override(&mut self) {
        let Some((task, spec)) = self.selected_planning_option_spec() else {
            return;
        };
        let Some(value) = self.planning_option_override_value(task, &spec.name) else {
            self.report_missing_planning_option_override();
            return;
        };
        self.persist_planning_option_override(task, &spec, value);
    }

    fn planning_option_override_value(
        &self,
        task: PlanningTaskId,
        option_name: &str,
    ) -> Option<Value> {
        self.planning_option_overrides
            .get(&task)
            .and_then(|values| values.get(option_name))
            .cloned()
    }

    fn report_missing_planning_option_override(&mut self) {
        self.planning_option_error =
            Some("S promotes a this-run override; edit this option first".to_string());
    }

    fn persist_planning_option_override(
        &mut self,
        task: PlanningTaskId,
        spec: &OptionSpec,
        value: Value,
    ) {
        let tool_name = task.tool_name().to_string();
        self.option_store.set_value(
            OptionScope::Global,
            OptionTarget::Tool(tool_name.clone()),
            spec.name.clone(),
            value.clone(),
        );
        self.clear_planning_option_override(task, &spec.name);
        self.persist_option_store(OptionScope::Global);
        self.planning_option_error = None;
        self.log_promoted_planning_option(&tool_name, spec, &value);
    }

    fn clear_planning_option_override(&mut self, task: PlanningTaskId, option_name: &str) {
        let Some(values) = self.planning_option_overrides.get_mut(&task) else {
            return;
        };
        values.remove(option_name);
        if values.is_empty() {
            self.planning_option_overrides.remove(&task);
        }
    }

    fn log_promoted_planning_option(&mut self, tool_name: &str, spec: &OptionSpec, value: &Value) {
        self.log(
            "setg",
            format!(
                "{}.{} = {}",
                tool_name,
                spec.name,
                format_option_value(value)
            ),
        );
    }
}
