use super::*;

impl ShellApp {
    pub(crate) fn show_kb(&mut self, module: Option<String>) {
        let module_id = match self.resolve_kb_module(module) {
            Ok(module_id) => module_id,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match self.refresh_kb_view(&module_id) {
            Ok(()) => {
                self.focused_module = Some(module_id.clone());
                self.shell_view = ShellView::KnowledgeBase;
                self.kb_scroll = 0;
                self.log(
                    "kb",
                    format!(
                        "{} attachment(s) for {module_id}. Next: attach <path-or-url>",
                        self.kb_view
                            .attachments
                            .iter()
                            .filter(|record| record.module_id == module_id)
                            .count()
                    ),
                );
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(crate) fn attach_kb_source(&mut self, source: &str) {
        let module_id = match self.resolve_kb_module(None) {
            Ok(module_id) => module_id,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match attach_source(&workspace, &module_id, source) {
            Ok(record) => {
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log(
                    "attach",
                    format!(
                        "{} {} ({})",
                        record.id,
                        record.source,
                        if record.metadata_only {
                            "metadata-only"
                        } else {
                            "local"
                        }
                    ),
                );
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }
}
