use super::*;

impl ShellApp {
    pub(crate) fn reduce_workspace_command_effects(
        &mut self,
        command: &WorkspaceCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            WorkspaceCommand::Status => Some(vec![ShellEffect::ShowWorkspaceStatus]),
            WorkspaceCommand::Reindex => {
                Some(vec![ShellEffect::WorkspaceReindex(WorkspaceReindex {
                    target: self.target_owned(),
                    changes: self.workspace_pending_changes(),
                })])
            }
            WorkspaceCommand::ScopeInit => {
                Some(vec![ShellEffect::WorkspaceScopeInit(WorkspaceScopeInit {
                    target: self.target_owned(),
                })])
            }
            WorkspaceCommand::ExportFindings {
                output,
                format,
                completeness,
                allow_empty,
            } => Some(vec![ShellEffect::WorkspaceExportFindings(
                WorkspaceExportFindings {
                    allow_empty: *allow_empty,
                    completeness: completeness.clone(),
                    format: format.clone(),
                    output: output.clone(),
                    target: self.target_owned(),
                },
            )]),
            WorkspaceCommand::Unsupported(raw) => {
                self.show_unsupported_workspace_command(raw);
                Some(Vec::new())
            }
        }
    }

    fn show_unsupported_workspace_command(&mut self, raw: &str) {
        let workspace_view = self.build_workspace_view(None);
        self.domain_mut().set_workspace_view(workspace_view);
        self.set_shell_view(ShellView::Workspace);
        if raw.starts_with("usage: ") {
            self.log("error", raw);
            return;
        }
        self.log(
            "error",
            format!(
                "{raw} is not supported by the Rust workspace bridge yet. Supported: workspace status, workspace reindex, workspace scope init, workspace export findings <path> [json|jsonl|sarif|csv|markdown-bundle] [--completeness open|complete] [--allow-empty]"
            ),
        );
    }

    pub(crate) fn show_history(&mut self) {
        self.set_shell_view(ShellView::History);
        self.router.history_mut().open();
        let count = self.command_history().len();
        self.log(
            "history",
            format!(
                "showing {count} {}. Next: clear or run <tool>",
                if count == 1 { "command" } else { "commands" }
            ),
        );
    }

    pub(crate) fn clear_conversation(&mut self) -> Vec<ShellEffect> {
        let live_agent_was_canceled = self.jobs_mut().cancel(JobKind::Agent);
        if live_agent_was_canceled && self.runtime_state.cleared_agent_run().is_none() {
            let run = crate::app::ClearedAgentRun {
                run_id: self.agent_chat().and_then(|agent| agent.run_id.clone()),
                started_secs: self
                    .agent_chat()
                    .map(|agent| agent.started_secs)
                    .unwrap_or_default(),
                artifact_target: self.agent_artifact_target_owned(),
                auxiliary_read_only: self
                    .agent_chat()
                    .is_some_and(|agent| agent.auxiliary_read_only),
            };
            self.runtime_state.remember_cleared_agent_run(run);
        } else if !live_agent_was_canceled {
            self.runtime_state.clear_cleared_agent_run();
            self.set_agent_cancel(None);
        }
        self.clear_log();
        *self.selected_finding_mut() = None;
        self.clear_agent_chat();
        self.set_shell_view(ShellView::Catalog);
        self.log(
            "system",
            "Conversation cleared. Command history retained. Next: history or help",
        );
        // Keep the canceled Agent slot occupied until its current generation
        // emits a terminal event. Releasing it here would let queued work run
        // concurrently with a non-cooperative worker that still has workspace
        // side effects in flight. `apply_job_event` drains steer after the
        // terminal event releases the slot.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::incremental_index::WorkspaceChange;
    use kuzushi_core::V2Config;

    #[test]
    fn workspace_reindex_command_returns_targeted_effect() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.apply_workspace_changes(&[WorkspaceChange::FileChanged("src/app.rs".into())]);

        let effects = app
            .reduce_workspace_command_effects(&WorkspaceCommand::Reindex)
            .expect("workspace command should be routed");

        assert_eq!(effects.len(), 1);
        match &effects[0] {
            ShellEffect::WorkspaceReindex(reindex) => {
                assert_eq!(reindex.target.as_deref(), Some(workspace.root()));
                assert_eq!(
                    reindex.changes,
                    vec![WorkspaceChange::FileChanged("src/app.rs".into())]
                );
            }
            _ => panic!("expected workspace reindex effect"),
        }
    }

    #[test]
    fn workspace_usage_error_hydrates_the_active_target_projection() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        app.reduce_workspace_command_effects(&WorkspaceCommand::Unsupported(
            "usage: findings export <path> [format]".to_string(),
        ));

        let model = crate::ui_view_models::workspace_model(&app);
        assert_eq!(app.shell_view(), ShellView::Workspace);
        assert!(!model.empty);
        assert_eq!(
            app.domain().workspace_view().root.as_deref(),
            Some(temp.path().canonicalize().unwrap().as_path())
        );
        assert_ne!(model.target_label, "none");
        assert!(model.status.starts_with("workspace ready"));
    }
}
