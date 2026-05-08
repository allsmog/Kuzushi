use super::*;

impl ShellApp {
    pub(crate) fn detach_kb_source(&mut self, id: &str) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match detach_source(&workspace, id) {
            Ok(record) => {
                let module_id = record.module_id.clone();
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log("detach", format!("removed {} {}", record.id, record.source));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(crate) fn reparse_kb_source(&mut self, id: &str) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match reparse_source(&workspace, id) {
            Ok(record) => {
                let module_id = record.module_id.clone();
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log("reparse", format!("{} {}", record.id, record.status));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(crate) fn refresh_kb_view(&mut self, module_id: &str) -> Result<()> {
        let workspace = self.current_workspace()?;
        let attachments = list_attachments(&workspace)?;
        let artifacts = known_artifacts(&workspace, module_id)?;
        self.kb_view = KnowledgeBaseView {
            module_id: module_id.to_string(),
            store_path: Some(attachment_store_path(&workspace)),
            attachments,
            artifacts,
        };
        Ok(())
    }

    pub(crate) fn resolve_kb_module(&self, requested: Option<String>) -> Result<String> {
        if let Some(module_id) = requested {
            let module_id = normalize_kb_module_id(&module_id);
            if is_supported_attachment_module(&module_id) {
                return Ok(module_id);
            }
            anyhow::bail!("{}", unknown_kb_module_message(&module_id));
        }

        if let Some(module_id) = self
            .focused_module
            .as_deref()
            .map(normalize_kb_module_id)
            .filter(|module_id| is_supported_attachment_module(module_id))
        {
            return Ok(module_id);
        }

        if is_supported_attachment_module(&self.kb_view.module_id) {
            return Ok(self.kb_view.module_id.clone());
        }

        Ok("context".to_string())
    }
}
