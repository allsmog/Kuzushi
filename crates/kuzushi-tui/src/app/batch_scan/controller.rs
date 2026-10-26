use super::launch::resolve_config_workers;
use super::worker_resolution::BatchWorkerResolution;
use super::{BatchScanConfig, BatchScanConfigRow};
use crate::app::state_transitions::{InputUpdate, ViewHotkeyAction};
use crate::app::{ShellApp, ShellView};

mod scope;
use scope::restore_scope_allowance;

impl ShellApp {
    pub(crate) fn open_selected_scopes_study(
        &mut self,
        draft: kuzushi_core::capabilities::campaign::ScopeStudyDraft,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work; marked boundaries are retained"
        );
        let target = self
            .target_owned()
            .ok_or_else(|| anyhow::anyhow!("Select a repository first"))?;
        self.refresh_phase_attempt_projection();
        let mut input = super::launch::preview_scan_input(self)?;
        input.as_object_mut().unwrap().remove("scanScopeRef");
        let mut config = BatchScanConfig::load_for_new_study(&target, None);
        config.scope_context.labels = self.scope_study_labels(&draft);
        config.study.scope_draft = Some(draft);
        let scoped = super::scope_study::picker_input(&config, input.clone());
        restore_scope_allowance(&mut config, &scoped)?;
        config.study.scan_input = Some(input);
        config.notice = Some("Marked boundaries only. Review engines, exact context, total jobs and shared allowance before approval. Sibling scopes remain unplanned.".into());
        self.show_study_form(config);
        self.refresh_batch_worker_resolution();
        Ok(())
    }

    fn scope_study_labels(
        &self,
        draft: &kuzushi_core::capabilities::campaign::ScopeStudyDraft,
    ) -> std::collections::BTreeMap<String, String> {
        let Some(review) = self
            .scope_review()
            .and_then(|state| state.review.as_deref())
            .filter(|review| review.reference == draft.proposal_ref)
        else {
            return Default::default();
        };
        review
            .record
            .draft
            .scopes
            .iter()
            .chain(review.record.draft.shared_scope.iter())
            .map(|scope| (scope.id.clone(), scope.name.clone()))
            .collect()
    }

    pub(crate) fn open_selected_scope_study(
        &mut self,
        reference: kuzushi_core::workspace::ScanScopeRef,
        summary: String,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work. Your scope selection is preserved."
        );
        let target = self
            .target_owned()
            .ok_or_else(|| anyhow::anyhow!("Select a repository first."))?;
        self.refresh_phase_attempt_projection();
        let mut input = super::launch::preview_scan_input(self)?;
        input["scanScopeRef"] = serde_json::json!(reference);
        let mut config = BatchScanConfig::load_for_new_study(&target, None);
        restore_scope_allowance(&mut config, &input)?;
        config.study.scan_input = Some(input);
        config.notice = Some(summary);
        self.show_study_form(config);
        self.refresh_batch_worker_resolution();
        Ok(())
    }

    pub(crate) fn open_batch_scan_config(&mut self, prior_run_id: Option<&str>) {
        let Some(target) = self.target_owned() else {
            self.log("batch", "scan batch requires an active target");
            return;
        };
        self.refresh_phase_attempt_projection();
        self.refresh_campaign_deck();
        self.show_study_form(BatchScanConfig::load_for_new_study(&target, prior_run_id));
        self.refresh_batch_worker_resolution();
        self.start_study_draft_recovery();
        self.log("batch", "scan-batch configurator");
    }

    pub(crate) fn apply_batch_scan_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if let Some(update) = self.apply_batch_cursor_hotkey(action) {
            return update;
        }
        if let Some(update) = self.apply_batch_edit_hotkey(action) {
            return update;
        }
        if let Some(update) = self.apply_batch_control_hotkey(action) {
            return update;
        }
        InputUpdate::ignored()
    }

    fn apply_batch_cursor_hotkey(&mut self, action: ViewHotkeyAction) -> Option<InputUpdate> {
        match action {
            ViewHotkeyAction::CampaignCursorPrevious => {
                Some(self.edit_batch_config(|c| c.move_cursor(-1)))
            }
            ViewHotkeyAction::CampaignCursorNext => {
                Some(self.edit_batch_config(|c| c.move_cursor(1)))
            }
            _ => None,
        }
    }

    fn apply_batch_edit_hotkey(&mut self, action: ViewHotkeyAction) -> Option<InputUpdate> {
        match action {
            ViewHotkeyAction::CampaignCycleWorkers => Some(self.edit_batch_config(|config| {
                config.begin_number_edit(BatchScanConfigRow::Workers);
            })),
            ViewHotkeyAction::CampaignOpenDetail => Some(self.activate_batch_config_row()),
            _ => None,
        }
    }

    fn apply_batch_control_hotkey(&mut self, action: ViewHotkeyAction) -> Option<InputUpdate> {
        match action {
            ViewHotkeyAction::CampaignLaunch => Some(self.launch_batch_from_config()),
            ViewHotkeyAction::CampaignBackToList => Some(self.close_batch_config()),
            ViewHotkeyAction::CampaignRefresh => Some(self.refresh_batch_config()),
            _ => None,
        }
    }

    fn edit_batch_config(&mut self, edit: impl FnOnce(&mut BatchScanConfig)) -> InputUpdate {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            edit(config);
        }
        InputUpdate::handled()
    }

    fn activate_batch_config_row(&mut self) -> InputUpdate {
        if let Some(update) = self.activate_study_subview() {
            return update;
        }
        let launch = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .is_some_and(BatchScanConfig::activate_selected);
        if launch {
            return self.launch_batch_from_config();
        }
        self.refresh_batch_worker_resolution();
        InputUpdate::handled()
    }

    fn activate_study_subview(&mut self) -> Option<InputUpdate> {
        let row = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .selected_row();
        match row {
            BatchScanConfigRow::PriorRun => self.open_study_resource_picker(),
            BatchScanConfigRow::Engines => Some(self.open_study_engine_picker()),
            BatchScanConfigRow::Context => Some(self.open_study_context_surface()),
            BatchScanConfigRow::Brief => Some(self.open_investigation_brief()),
            BatchScanConfigRow::ContextComparison => Some(self.toggle_context_experiment()),
            BatchScanConfigRow::ContextCases => Some(self.open_context_matrix()),
            _ => None,
        }
    }

    pub(super) fn set_batch_config_notice(&mut self, notice: impl Into<String>) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.notice = Some(notice.into());
        }
    }

    pub(super) fn close_batch_config(&mut self) -> InputUpdate {
        self.checkpoint_study_choices();
        if self.keep_model_study_choices() || self.keep_uncheckpointed_study_choices() {
            return InputUpdate::handled();
        }
        self.finish_closing_study()
    }

    pub(in crate::app::batch_scan) fn finish_closing_study(&mut self) -> InputUpdate {
        let config = self.router.campaign_mut().batch_scan_config.take();
        let origin = match config {
            Some(config) if config.dfd_origin.is_some() => {
                return self.restore_dfd_study_origin(config)
            }
            config => config.and_then(|config| config.origin),
        };
        self.restore_study_navigation(origin);
        InputUpdate::handled()
    }

    pub(super) fn restore_study_navigation(
        &mut self,
        origin: Option<super::config::StudyNavigationOrigin>,
    ) {
        let Some(origin) = origin else {
            self.open_campaign_view(None);
            return;
        };
        self.set_shell_view(origin.view);
        self.set_input_mode(origin.mode);
        *self.router.workbench_mut() = origin.workbench;
        match origin.phase {
            Some(phase) => self.engagement.set_phase(phase),
            None => self.engagement.clear_phase(),
        }
        if let Some(scope) = self.router.scope_review_mut().as_mut() {
            scope.open = origin.scope_review;
        }
    }

    fn keep_uncheckpointed_study_choices(&mut self) -> bool {
        if self.study_choices_checkpointed() {
            return false;
        }
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return false;
        };
        if config.draft_recovery != super::StudyDraftRecovery::None
            || !self.study_choices_not_checkpointed()
        {
            return false;
        }
        self.keep_pending_study_choices()
    }

    fn keep_pending_study_choices(&mut self) -> bool {
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        if !config.study.matrix.has_unsaved_changes() {
            config.draft_recovery = super::StudyDraftRecovery::Discard;
            return true;
        }
        config.study.matrix.open = true;
        config.notice = Some("These context cases are not saved yet. L prepares a recoverable draft; c clears them before Back.".into());
        true
    }

    pub(super) fn show_study_form(&mut self, mut config: BatchScanConfig) {
        config.origin = Some(super::config::StudyNavigationOrigin {
            view: self.shell_view(),
            mode: self.input_mode(),
            workbench: self.router.workbench().clone(),
            scope_review: self.scope_review_is_visible(),
            phase: self.engagement.current_phase(),
        });
        self.clear_notice();
        if let Some(scope) = self.router.scope_review_mut().as_mut() {
            scope.open = false;
        }
        self.router.campaign_mut().batch_scan_config = Some(config);
        self.initialize_study_checkpoint_baseline();
        self.set_shell_view(ShellView::Campaign);
        self.set_input_mode(crate::app::InputMode::Navigate);
    }

    fn refresh_batch_config(&mut self) -> InputUpdate {
        let Some(target) = self.target_owned() else {
            return InputUpdate::handled();
        };
        self.invalidate_view_hydration();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_study_usage(&target);
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.reset_usage_loading();
        }
        self.refresh_study_allowance();
        self.refresh_batch_worker_resolution();
        self.schedule_active_view_hydration();
        self.retry_context_baseline_allowance()
            .unwrap_or_else(InputUpdate::handled)
    }

    pub(in crate::app) fn refresh_batch_worker_resolution(&mut self) {
        let Some((target, config)) = self
            .target_owned()
            .zip(self.router.campaign().batch_scan_config.clone())
        else {
            return;
        };
        if config.study.accounting_error.is_some() {
            return;
        }
        match resolve_config_workers(self, &target, &config) {
            Ok(resolution) => self.apply_batch_worker_resolution(resolution),
            Err(error) => {
                self.set_batch_config_notice(format!("worker policy unavailable: {error:#}"))
            }
        }
    }

    fn apply_batch_worker_resolution(&mut self, resolution: BatchWorkerResolution) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.apply_worker_resolution(resolution.effective_workers, resolution.reason);
        }
    }
}
