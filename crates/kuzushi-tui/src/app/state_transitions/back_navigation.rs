use super::*;

impl ShellApp {
    /// Pop the most recent entry off `nav_history` and switch to it.
    /// Falls back to `Workbench` when the stack is empty (e.g. first
    /// command after boot). The stack is maintained by `sync_view_change`
    /// — every transition into a new view pushes the prior view here.
    pub(crate) fn go_back(&mut self) {
        match self.nav_history.pop() {
            Some(ShellView::Home) => {
                self.focused_module = None;
                self.catalog_expanded = false;
                self.shell_view = ShellView::Home;
            }
            Some(target) => {
                self.shell_view = target;
            }
            None => {
                self.open_workbench(WorkbenchPane::Findings);
            }
        }
    }
}
