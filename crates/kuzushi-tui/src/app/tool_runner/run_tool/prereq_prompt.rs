use super::*;

impl ShellApp {
    #[allow(dead_code)] // exercised by tests; the lib lint can't see test usage
    pub(crate) fn resolve_prereq_prompt(&mut self, reuse: bool) {
        let action = if reuse {
            PrereqPlanAction::Reuse
        } else {
            PrereqPlanAction::Regenerate
        };
        self.resolve_prereq_plan(action);
    }
}
