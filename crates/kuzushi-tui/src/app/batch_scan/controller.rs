use super::launch::{prepare_batch_launch, resolve_config_workers, PreparedBatchLaunch};
use super::worker_resolution::BatchWorkerResolution;
use super::BatchScanConfig;
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
        self.router.campaign_mut().batch_scan_config =
            Some(BatchScanConfig::load(&target, prior_run_id));
        self.refresh_batch_worker_resolution();
        self.set_shell_view(ShellView::Campaign);
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
            ViewHotkeyAction::CampaignCycleWorkers => {
                Some(self.edit_batch_config_and_resolve(BatchScanConfig::cycle_workers))
            }
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

    fn edit_batch_config_and_resolve(
        &mut self,
        edit: impl FnOnce(&mut BatchScanConfig),
    ) -> InputUpdate {
        self.edit_batch_config(edit);
        self.refresh_batch_worker_resolution();
        InputUpdate::handled()
    }

    fn activate_batch_config_row(&mut self) -> InputUpdate {
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

    fn launch_batch_from_config(&mut self) -> InputUpdate {
        let Some(config) = self.confirmed_batch_config() else {
            return InputUpdate::handled();
        };
        let Some(target) = self.target_owned() else {
            self.set_batch_config_notice("scan batch requires an active target");
            return InputUpdate::handled();
        };
        match prepare_batch_launch(self, &target, &config) {
            Ok(launch) => self.start_compiled_batch(launch),
            Err(error) => self.set_batch_config_notice(format!("batch plan failed: {error:#}")),
        }
        InputUpdate::handled()
    }

    fn confirmed_batch_config(&mut self) -> Option<BatchScanConfig> {
        let config = self.router.campaign_mut().batch_scan_config.as_mut()?;
        if config.needs_large_batch_review() && !config.review_armed {
            config.arm_review();
            return None;
        }
        Some(config.clone())
    }

    fn start_compiled_batch(&mut self, launch: PreparedBatchLaunch) {
        let batch_id = launch.plan.campaign_id.clone();
        self.router.campaign_mut().batch_scan_config = None;
        self.router.campaign_mut().active_batch_id = Some(batch_id.clone());
        self.open_campaign_view(Some(batch_id.clone()));
        let deck = self.router.campaign_mut();
        deck.detail = true;
        deck.workers = launch.effective_workers;
        deck.notice = launch.clamp_reason;
        self.refresh_active_batch_report();
        self.launch_selected_campaign();
    }

    fn set_batch_config_notice(&mut self, notice: impl Into<String>) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.notice = Some(notice.into());
        }
    }

    fn close_batch_config(&mut self) -> InputUpdate {
        self.router.campaign_mut().batch_scan_config = None;
        self.open_campaign_view(None);
        InputUpdate::handled()
    }

    fn refresh_batch_config(&mut self) -> InputUpdate {
        let previous = self.router.campaign().batch_scan_config.clone();
        let Some((target, previous)) = self.target_owned().zip(previous) else {
            return InputUpdate::handled();
        };
        let mut refreshed = BatchScanConfig::load(&target, previous.prior_run_id.as_deref());
        refreshed.trials = previous.trials;
        refreshed.requested_workers = previous.requested_workers;
        refreshed.cursor = previous.cursor;
        self.router.campaign_mut().batch_scan_config = Some(refreshed);
        self.refresh_batch_worker_resolution();
        InputUpdate::handled()
    }

    fn refresh_batch_worker_resolution(&mut self) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn prelaunch_refresh_projects_planned_trials_instead_of_an_unavailable_report() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("source.rs"), "fn main() {}\n").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        let config = BatchScanConfig::load(target.path(), None);
        let launch = prepare_batch_launch(&app, target.path(), &config).unwrap();
        let batch_id = launch.plan.campaign_id;
        app.router.campaign_mut().active_batch_id = Some(batch_id);

        app.refresh_active_batch_report();

        let deck = app.router.campaign();
        let report = deck.active_batch_report().expect("prelaunch report");
        assert_eq!((report.planned, report.completed), (config.trials, 0));
        assert_eq!((report.failed, report.pending), (0, config.trials));
        assert!(deck
            .notice
            .as_deref()
            .is_none_or(|notice| !notice.contains("report unavailable")));
    }
}
