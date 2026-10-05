use super::launch::resolve_config_workers;
use super::worker_resolution::BatchWorkerResolution;
use super::{BatchScanConfig, BatchScanConfigRow};
use crate::app::state_transitions::{InputUpdate, ViewHotkeyAction};
use crate::app::{ShellApp, ShellView};
use kuzushi_core::findings::derive_batch_occurrence_report;

impl ShellApp {
    pub(crate) fn open_batch_scan_config(&mut self, prior_run_id: Option<&str>) {
        let Some(target) = self.target_owned() else {
            self.log("batch", "scan batch requires an active target");
            return;
        };
        self.refresh_campaign_deck();
        self.show_study_form(BatchScanConfig::load(&target, prior_run_id));
        self.refresh_batch_worker_resolution();
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
        if self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .is_some_and(|config| config.selected_row() == BatchScanConfigRow::Context)
        {
            return self.open_study_context_picker();
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

    pub(super) fn set_batch_config_notice(&mut self, notice: impl Into<String>) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.notice = Some(notice.into());
        }
    }

    pub(super) fn close_batch_config(&mut self) -> InputUpdate {
        let origin = self
            .router
            .campaign_mut()
            .batch_scan_config
            .take()
            .and_then(|config| config.origin);
        if let Some(origin) = origin {
            self.set_shell_view(origin.view);
            self.set_input_mode(origin.mode);
            *self.router.workbench_mut() = origin.workbench;
        } else {
            self.open_campaign_view(None);
        }
        InputUpdate::handled()
    }

    pub(super) fn show_study_form(&mut self, mut config: BatchScanConfig) {
        config.origin = Some(super::config::StudyNavigationOrigin {
            view: self.shell_view(),
            mode: self.input_mode(),
            workbench: self.router.workbench().clone(),
        });
        self.router.campaign_mut().batch_scan_config = Some(config);
        self.set_shell_view(ShellView::Campaign);
        self.set_input_mode(crate::app::InputMode::Navigate);
    }

    fn refresh_batch_config(&mut self) -> InputUpdate {
        let previous = self.router.campaign().batch_scan_config.clone();
        let Some((target, previous)) = self.target_owned().zip(previous) else {
            return InputUpdate::handled();
        };
        let prior = BatchScanConfig::load(&target, previous.prior_run_id.as_deref());
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.prior_runs = prior.prior_runs;
            config.prior_run_cost_usd = prior.prior_run_cost_usd;
        }
        self.refresh_study_allowance();
        self.refresh_batch_worker_resolution();
        InputUpdate::handled()
    }

    pub(super) fn refresh_batch_worker_resolution(&mut self) {
        let Some((target, config)) = self
            .target_owned()
            .zip(self.router.campaign().batch_scan_config.clone())
        else {
            return;
        };
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

    pub(crate) fn open_batch_results(&mut self, batch_id: &str) {
        self.open_campaign_view(Some(batch_id.to_string()));
        let is_batch = self
            .router
            .campaign()
            .selected_campaign()
            .is_some_and(super::is_scan_batch_snapshot);
        if !is_batch {
            self.router.campaign_mut().notice =
                Some(format!("campaign {batch_id:?} is not a scan batch"));
            return;
        }
        let deck = self.router.campaign_mut();
        deck.detail = true;
        deck.active_batch_id = Some(batch_id.to_string());
        self.refresh_active_batch_report();
    }

    pub(crate) fn clear_batch_scope(&mut self) {
        self.router.campaign_mut().clear_active_batch();
        self.log("batch", "batch Review scope cleared");
    }

    pub(crate) fn refresh_active_batch_report(&mut self) {
        let Some((target, batch_id)) = self
            .target_owned()
            .zip(self.router.campaign().active_batch_id.clone())
        else {
            return;
        };
        let report = self
            .open_store()
            .and_then(|store| derive_batch_occurrence_report(&target, &batch_id, &store));
        self.apply_batch_report(batch_id, report);
    }

    fn apply_batch_report(
        &mut self,
        batch_id: String,
        report: anyhow::Result<kuzushi_core::findings::BatchOccurrenceReport>,
    ) {
        match report {
            Ok(report) => self.router.campaign_mut().active_batch_report = Some(report),
            Err(error) => {
                let deck = self.router.campaign_mut();
                deck.active_batch_report = None;
                deck.notice = Some(format!("batch {batch_id} report unavailable: {error:#}"));
            }
        }
    }
}
