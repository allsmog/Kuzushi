//! Preserve exact navigation and study selection for linked ledger readers.
use super::*;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LinkedFindingsOrigin {
    pub(super) target: PathBuf,
    pub(super) query: String,
    view: ShellView,
    input_mode: crate::InputMode,
    overlay_origin: Option<ShellView>,
    overlay_input_mode: Option<crate::InputMode>,
    workbench: crate::app::WorkbenchRouteState,
    findings: crate::app::FindingsRouteState,
    findings_page: kuzushi_core::findings::FindingPageRequest,
    navigation: crate::app::NavigationRouteState,
    study_id: Option<String>,
    study_report: Option<kuzushi_core::findings::BatchOccurrenceReport>,
    study_members: std::collections::BTreeSet<String>,
    pub(super) batch_config: Option<Box<crate::app::BatchScanConfig>>,
}

impl ShellApp {
    pub(crate) fn capture_linked_findings_origin(
        &mut self,
        target: PathBuf,
        query: String,
    ) -> LinkedFindingsOrigin {
        let origin = LinkedFindingsOrigin {
            target,
            query,
            view: self.shell_view(),
            input_mode: self.input_mode(),
            overlay_origin: self.router.overlay_origin(),
            overlay_input_mode: self.router.overlay_input_mode(),
            workbench: self.router.workbench().clone(),
            findings: self.router.findings().clone(),
            findings_page: self.findings_page_request(self.active_findings_filter().as_deref()),
            navigation: self.router.navigation().clone(),
            batch_config: self
                .router
                .campaign_mut()
                .batch_scan_config
                .take()
                .map(Box::new),
            study_id: self.router.campaign().active_batch_id.clone(),
            study_report: self.router.campaign().active_batch_report.clone(),
            study_members: self
                .router
                .campaign()
                .active_batch_observation_fingerprints
                .clone(),
        };
        origin
    }

    pub(crate) fn restore_linked_findings_origin(&mut self, origin: LinkedFindingsOrigin) {
        self.set_shell_view(origin.view);
        *self.router.workbench_mut() = origin.workbench;
        *self.router.findings_mut() = origin.findings;
        *self.router.navigation_mut() = origin.navigation;
        self.router.campaign_mut().batch_scan_config = origin.batch_config.map(|config| *config);
        self.router.set_overlay_origin(origin.overlay_origin);
        self.router
            .set_overlay_input_mode(origin.overlay_input_mode);
        self.restore_linked_study(origin.study_id, origin.study_report, origin.study_members);
        self.set_input_mode(origin.input_mode);
        self.router
            .navigation_mut()
            .accept_back_transition(origin.view);
        self.runtime_state.requested_findings_page = Some(origin.findings_page);
        self.defer_findings_refresh(
            FindingsRefresh {
                announce: false,
                filter: self.active_findings_filter().clone(),
            },
            Vec::new(),
        );
    }

    fn restore_linked_study(
        &mut self,
        id: Option<String>,
        report: Option<kuzushi_core::findings::BatchOccurrenceReport>,
        members: std::collections::BTreeSet<String>,
    ) {
        let campaign = self.router.campaign_mut();
        campaign.active_batch_id = id;
        campaign.active_batch_report = report;
        campaign.active_batch_observation_fingerprints = members;
    }

    pub(crate) fn linked_findings_origin_matches(&self, origin: &LinkedFindingsOrigin) -> bool {
        self.target() == Some(origin.target.as_path())
            && self.router.workbench().page() == Some(crate::app::WorkbenchPage::Review)
    }
}
