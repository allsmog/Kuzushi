use super::*;

impl ShellApp {
    pub(crate) fn resolve_prereq_prompt(&mut self, reuse: bool) {
        let action = if reuse {
            PrereqPlanAction::Reuse
        } else {
            PrereqPlanAction::Regenerate
        };
        self.resolve_prereq_plan(action);
    }
}
