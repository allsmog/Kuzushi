use super::*;

impl ShellApp {
    pub(crate) fn show_options(&mut self, tool: Option<String>, filter: OptionsFilter) {
        let tool_name = match self.resolve_options_tool(tool) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };

        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            "options",
            format!("showing {} for {tool_name}", options_filter_label(filter)),
        );
    }
}
