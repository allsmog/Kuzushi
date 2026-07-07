macro_rules! shell_app_initial_state {
    ($config:expr, $target:expr, $option_store:expr, $registry:expr, $selected_model_index:expr, $session_budget_usd:expr, $trusted_workflow_auto_accept:expr) => {{
        let mut router = RouterState::default();
        router
            .model_catalog_mut()
            .set_selected_index($selected_model_index);
        Self {
            editor: EditorState::default(),
            log: LogState::default(),
            task_durations: crate::app::TaskDurationStore::load(
                ($target).map(|target| target.root()),
            ),
            shell_view: ShellView::Catalog,
            session: SessionState::new(
                $config,
                $registry,
                $option_store.clone(),
                ($target).map(|target| target.root().to_path_buf()),
                $session_budget_usd,
                $trusted_workflow_auto_accept,
            ),
            domain: DomainCache::new(
                default_context_snapshot_view(context_snapshot_target_path($target)),
                default_workspace_view($target),
                KnowledgeBaseView {
                    module_id: "context".to_string(),
                    store_path: None,
                    attachments: Vec::new(),
                    artifacts: Vec::new(),
                },
            ),
            agent_chat: AgentChatState::default(),
            workbench_cache: std::cell::RefCell::new(WorkbenchCache::default()),
            scan: ScanState::default(),
            advisory: AdvisoryState::default(),
            engagement: EngagementState::default(),
            router,
            ui: UiPrefs::new(
                read_auto_open_activity_pref(&$option_store),
                read_auto_open_viz_pref(&$option_store),
            ),
            jobs: JobHub::default(),
            runtime_state: RuntimeState::default(),
            tool_run: ToolRunState::default(),
            #[cfg(test)]
            option_persistence_enabled_for_test: true,
        }
    }};
}
