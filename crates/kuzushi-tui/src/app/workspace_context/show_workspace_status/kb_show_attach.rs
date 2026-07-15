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
                self.set_focused_module(Some(module_id.clone()));
                self.set_shell_view(ShellView::KnowledgeBase);
                self.router.kb_mut().open();
                self.log(
                    "kb",
                    format!(
                        "{} attachment(s) for {module_id}. Next: attach <path-or-url>",
                        self.domain()
                            .kb_view()
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
        let (workspace, module_id) = match self.kb_attachment_context() {
            Ok(context) => context,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match attach_source(&workspace, &module_id, source) {
            Ok(record) => self.accept_kb_attachment(module_id, record),
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn kb_attachment_context(&self) -> Result<(WorkspaceTarget, String)> {
        let module_id = self.resolve_kb_module(None)?;
        let workspace = self.current_workspace()?;
        Ok((workspace, module_id))
    }

    fn accept_kb_attachment(&mut self, module_id: String, record: kuzushi_core::AttachmentRecord) {
        let _ = self.refresh_kb_view(&module_id);
        self.set_focused_module(Some(module_id));
        self.set_shell_view(ShellView::KnowledgeBase);
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::AttachmentRef {
                attachment_id: record.id.clone(),
                path: (!record.metadata_only).then(|| std::path::PathBuf::from(&record.source)),
                digest: record.content_hash.clone(),
            },
        );
        let kind = if record.metadata_only {
            "metadata-only"
        } else {
            "local"
        };
        self.log(
            "attach",
            format!("{} {} ({kind})", record.id, record.source),
        );
    }
}
