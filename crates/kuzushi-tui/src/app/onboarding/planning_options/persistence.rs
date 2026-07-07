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
        self.engagement.option_override_value(task, option_name)
    }

    fn report_missing_planning_option_override(&mut self) {
        self.engagement
            .planning_picker_mut()
            .set_option_error("S promotes a this-run override; edit this option first");
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
        self.engagement.planning_picker_mut().clear_option_error();
        self.log_promoted_planning_option(&tool_name, spec, &value);
    }

    fn clear_planning_option_override(&mut self, task: PlanningTaskId, option_name: &str) {
        self.engagement.remove_option_override(task, option_name);
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
