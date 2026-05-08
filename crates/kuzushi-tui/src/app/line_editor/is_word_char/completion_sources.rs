use super::*;

impl ShellApp {
    pub(in crate::app::line_editor) fn module_completion_values(&self) -> Vec<String> {
        self.registry
            .modules()
            .map(|module| module.metadata().id.clone())
            .collect()
    }

    pub(in crate::app::line_editor) fn tool_completion_values(&self) -> Vec<String> {
        let mut values = self
            .registry
            .tools()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        if let Some(module) = self.focused_module.as_ref() {
            let prefix = format!("{module}:");
            values.extend(self.registry.tools().filter_map(|tool| {
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
            .and_then(|tool_name| self.registry.resolve_tool(&tool_name))
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

    pub(in crate::app::line_editor) fn attachment_id_completion_values(&self) -> Vec<String> {
        self.kb_view
            .attachments
            .iter()
            .map(|record| record.id.clone())
            .collect()
    }

    pub(in crate::app::line_editor) fn finding_completion_values(&self) -> Vec<String> {
        let mut findings = self.findings.clone();
        if findings.is_empty() {
            if let Some(target) = self.target.as_ref() {
                if let Ok(workspace) = WorkspaceTarget::new(target) {
                    if let Ok(store) = FindingStore::open(workspace.findings_db_path()) {
                        if let Ok(stored) = store.list_findings(200) {
                            findings = stored;
                        }
                    }
                }
            }
        }

        let mut values = Vec::new();
        for (alias, finding) in sorted_finding_aliases(&findings) {
            values.push(alias);
            values.push(short_fingerprint(&finding.fingerprint));
            values.push(finding.fingerprint.clone());
        }
        values
    }

    pub(in crate::app::line_editor) fn run_id_completion_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        if let Some(run_id) = self.scan.as_ref().and_then(|scan| scan.run_id.clone()) {
            values.push(run_id);
        }
        if let Some(target) = self.target.as_ref() {
            let runs_dir = target.join(".kuzushi/runs");
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
