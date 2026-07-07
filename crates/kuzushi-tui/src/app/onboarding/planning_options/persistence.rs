use crate::app::{
    format_option_value, PlanningOptionOverridePersist, PlanningTaskId, ShellApp, ShellEffect,
};
use kuzushi_core::{OptionScope, OptionTarget};
use serde_json::Value;

impl ShellApp {
    pub(crate) fn reduce_persist_selected_planning_option_override(&mut self) -> Vec<ShellEffect> {
        let Some((task, spec)) = self.selected_planning_option_spec() else {
            return Vec::new();
        };
        let Some(value) = self.planning_option_override_value(task, &spec.name) else {
            self.report_missing_planning_option_override();
            return Vec::new();
        };
        vec![ShellEffect::PersistPlanningOptionOverride(
            PlanningOptionOverridePersist {
                task,
                tool_name: task.tool_name().to_string(),
                option_name: spec.name,
                value,
            },
        )]
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

    pub(crate) fn persist_planning_option_override_effect(
        &mut self,
        persist: PlanningOptionOverridePersist,
    ) {
        self.option_store_mut().set_value(
            OptionScope::Global,
            OptionTarget::Tool(persist.tool_name.clone()),
            persist.option_name.clone(),
            persist.value.clone(),
        );
        self.clear_planning_option_override(persist.task, &persist.option_name);
        self.persist_option_store(OptionScope::Global);
        self.engagement.planning_picker_mut().clear_option_error();
        self.log_promoted_planning_option(&persist);
    }

    fn clear_planning_option_override(&mut self, task: PlanningTaskId, option_name: &str) {
        self.engagement.remove_option_override(task, option_name);
    }

    fn log_promoted_planning_option(&mut self, persist: &PlanningOptionOverridePersist) {
        self.log(
            "setg",
            format!(
                "{}.{} = {}",
                persist.tool_name,
                persist.option_name,
                format_option_value(&persist.value)
            ),
        );
    }
}
