use super::*;

impl ShellApp {
    /// Pop the most recent entry off the router navigation stack and switch to it.
    /// Falls back to `Workbench` when the stack is empty (e.g. first
    /// command after boot). The stack is maintained by `sync_view_change`
    /// — every transition into a new view pushes the prior view here.
    pub(crate) fn go_back(&mut self) {
        if self.close_model_picker_if_open() {
            return;
        }
        if self.restore_contextual_surface_origin() {
            return;
        }
        match self.router.navigation_mut().pop_history() {
            Some(ShellView::Home) => {
                self.clear_focused_module();
                self.router.catalog_mut().collapse();
                self.open_workbench();
            }
            Some(target) => {
                self.set_shell_view(target);
            }
            None => {
                self.open_workbench();
            }
        }
        let destination = self.shell_view();
        self.router
            .navigation_mut()
            .accept_back_transition(destination);
    }
}
