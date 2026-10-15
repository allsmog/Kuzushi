use super::*;

impl ShellApp {
    pub(super) fn retain_failed_setup_launch(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        message: &str,
    ) {
        if !self.is_current_setup_launch(workspace, tool_name) {
            return;
        }
        let Some(step) = self.engagement.take_running_planning_run_step() else {
            return;
        };
        self.engagement.push_expanded_step_front(step);
        self.engagement.pause_planning_queue();
        self.router
            .setup_mut()
            .record_launch_failure(message.to_string());
    }

    fn is_current_setup_launch(&self, workspace: &WorkspaceTarget, tool_name: &str) -> bool {
        self.shell_view() == ShellView::Setup
            && self.target() == Some(workspace.root())
            && self.engagement.running_tool_is(tool_name)
    }
}
