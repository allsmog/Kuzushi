use super::*;

impl EffectRuntime {
    pub(super) fn execute_persistence_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::PersistCommandHistory => app.persist_command_history(),
            ShellEffect::RecordAgentRun(record) => app.record_agent_run_effect(record),
            ShellEffect::RecordScanRun(record) => app.record_scan_run_effect(record),
            ShellEffect::RecordScanStageTrace(record) => app.record_scan_stage_trace_effect(record),
            ShellEffect::RecordToolRun(record) => app.record_tool_run_effect(record),
            ShellEffect::PersistGlobalModelSelection(selection) => {
                app.persist_global_model_selection_effect(selection)
            }
            ShellEffect::PersistPlanningOptionOverride(persist) => {
                app.persist_planning_option_override_effect(persist)
            }
            ShellEffect::PersistOptions(scope) => app.persist_option_store(scope),
            _ => unreachable!("persistence effect dispatch"),
        }
    }
}
