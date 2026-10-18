use super::*;

#[derive(Debug, Clone, PartialEq)]
pub(in crate::app::batch_scan) struct DfdStudyOrigin {
    target: std::path::PathBuf,
    scene: crate::app::SceneRouteState,
    overlay: Option<ShellView>,
    overlay_mode: Option<crate::app::InputMode>,
    parent: Option<Box<BatchScanConfig>>,
}

impl ShellApp {
    pub(in crate::app::batch_scan) fn retain_dfd_study_return(&mut self, config: &BatchScanConfig) {
        if config.dfd_origin.is_some() {
            self.router.campaign_mut().dfd_study_return = Some(Box::new(config.clone()));
        }
    }

    pub(crate) fn dfd_study_jobs_navigation_active(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self.router.campaign().batch_scan_config.is_none()
            && self.router.campaign().dfd_study_return.is_some()
    }

    pub(crate) fn restore_dfd_study_jobs_origin(&mut self) -> bool {
        if !self.dfd_study_jobs_navigation_active() || self.router.campaign().job_detail {
            return false;
        }
        let config = self.router.campaign_mut().dfd_study_return.take().unwrap();
        self.restore_dfd_study_origin(*config);
        true
    }

    pub(super) fn install_dfd_study(&mut self, mut config: BatchScanConfig) {
        self.checkpoint_study_choices();
        config.dfd_origin = Some(Box::new(DfdStudyOrigin {
            target: config.target.clone(),
            scene: self.router.scene().clone(),
            overlay: self.router.overlay_origin(),
            overlay_mode: self.router.overlay_input_mode(),
            parent: self
                .router
                .campaign_mut()
                .batch_scan_config
                .take()
                .map(Box::new),
        }));
        self.show_study_form(config);
    }

    pub(in crate::app::batch_scan) fn restore_dfd_study_origin(
        &mut self,
        mut config: BatchScanConfig,
    ) -> InputUpdate {
        let origin = config.dfd_origin.take().unwrap();
        if self.target() != Some(origin.target.as_path()) {
            self.open_campaign_view(None);
            self.set_warn_notice(
                "DFD scan plan",
                "Target changed. The earlier diagram was not restored.",
            );
            return InputUpdate::handled();
        }
        self.restore_study_navigation(config.origin.take());
        *self.router.scene_mut() = origin.scene;
        self.router.set_overlay_origin(origin.overlay);
        self.router.set_overlay_input_mode(origin.overlay_mode);
        self.router.campaign_mut().batch_scan_config = origin.parent.map(|parent| *parent);
        self.refresh_dfd_parent_accounting(&config);
        let view = self.shell_view();
        self.router.navigation_mut().accept_back_transition(view);
        InputUpdate::handled()
    }
}
