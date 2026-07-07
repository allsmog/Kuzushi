use super::*;

impl ShellApp {
    pub(in crate::app::line_editor) fn module_completion_values(&self) -> Vec<String> {
        self.registry()
            .modules()
            .map(|module| module.metadata().id.clone())
            .collect()
    }

    pub(in crate::app::line_editor) fn tool_completion_values(&self) -> Vec<String> {
        let mut values = self
            .registry()
            .tools()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        if let Some(module) = self.focused_module() {
            let prefix = format!("{module}:");
            values.extend(self.registry().tools().filter_map(|tool| {
                tool.name
                    .strip_prefix(&prefix)
                    .map(|short_name| short_name.to_string())
            }));
        }
        values
    }

    pub(in crate::app::line_editor) fn option_completion_values(&self) -> Vec<String> {
        self.resolve_options_tool(None)
            .ok()
            .and_then(|tool_name| self.registry().resolve_tool(&tool_name))
            .map(|tool| tool.options.iter().map(|spec| spec.name.clone()).collect())
            .unwrap_or_default()
    }

    pub(in crate::app::line_editor) fn task_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(self, TASK_COMPLETION_RULES, slash, prefix_words, current)
    }

    pub(in crate::app::line_editor) fn context_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(self, CONTEXT_COMPLETION_RULES, slash, prefix_words, current)
    }

    pub(in crate::app::line_editor) fn workspace_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(
            self,
            WORKSPACE_COMPLETION_RULES,
            slash,
            prefix_words,
            current,
        )
    }

    pub(in crate::app::line_editor) fn auth_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(self, AUTH_COMPLETION_RULES, slash, prefix_words, current)
    }

    pub(in crate::app::line_editor) fn show_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(self, SHOW_COMPLETION_RULES, slash, prefix_words, current)
    }

    pub(in crate::app::line_editor) fn threats_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(self, THREATS_COMPLETION_RULES, slash, prefix_words, current)
    }

    pub(in crate::app::line_editor) fn prompt_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        complete_subcommand_rules(self, PROMPT_COMPLETION_RULES, slash, prefix_words, current)
    }

    pub(in crate::app::line_editor) fn attachment_id_completion_values(&self) -> Vec<String> {
        self.domain()
            .kb_view()
            .attachments
            .iter()
            .map(|record| record.id.clone())
            .collect()
    }

    pub(in crate::app::line_editor) fn finding_completion_values(&self) -> Vec<String> {
        finding_completion_values_for_target(self.target_path_buf(), self.findings())
    }

    pub(in crate::app::line_editor) fn run_id_completion_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        if let Some(run_id) = self.scan().and_then(|scan| scan.run_id.clone()) {
            values.push(run_id);
        }
        if let Some(target) = self.target_path_buf() {
            let runs_dir = kuzushi_core::runs_root(target);
            if let Ok(entries) = fs::read_dir(runs_dir) {
                values.extend(entries.flatten().filter_map(|entry| {
                    entry
                        .file_type()
                        .ok()
                        .filter(|file_type| file_type.is_dir())
                        .and_then(|_| entry.file_name().into_string().ok())
                }));
            }
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanPanelState;
    use kuzushi_core::V2Config;
    use std::path::PathBuf;

    #[test]
    fn run_id_completion_values_read_shared_runs_root() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(kuzushi_core::run_dir(temp.path(), "r-past")).unwrap();
        std::fs::write(kuzushi_core::runs_root(temp.path()).join("not-a-run"), "").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.set_scan_panel(Some(ScanPanelState {
            run_id: Some("r-active".to_string()),
            target: PathBuf::from("/tmp/demo"),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));

        let values = app.run_id_completion_values();

        assert!(values.contains(&"r-active".to_string()));
        assert!(values.contains(&"r-past".to_string()));
        assert!(!values.contains(&"not-a-run".to_string()));
    }
}
