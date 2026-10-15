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

        if self.shell_view() != ShellView::Options {
            self.router.options_browser_mut().support_origin = None;
        }

        self.router.set_options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.set_shell_view(ShellView::Options);
        self.router.answers_mut().focus = crate::app::AnswerFocus::Workspace;
        self.set_input_mode(crate::app::InputMode::Navigate);
        self.log(
            "options",
            format!("showing {} for {tool_name}", options_filter_label(filter)),
        );
    }
}
