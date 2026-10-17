use super::*;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdReviewOrigin {
    target: PathBuf,
    query: String,
    view: ShellView,
    input_mode: crate::InputMode,
    overlay_origin: Option<ShellView>,
    overlay_input_mode: Option<crate::InputMode>,
    workbench: crate::app::WorkbenchRouteState,
    findings: crate::app::FindingsRouteState,
    findings_page: kuzushi_core::findings::FindingPageRequest,
    navigation: crate::app::NavigationRouteState,
    batch_config: Option<Box<crate::app::BatchScanConfig>>,
}

impl ShellApp {
    pub(super) fn is_dfd_findings_key(&self, key: KeyEvent) -> bool {
        self.router.scene().page() == crate::scene3d::VizPage::Dfd && key.code == KeyCode::Char('f')
    }

    pub(super) fn open_selected_dfd_findings(&mut self) -> InputUpdate {
        let model = crate::ui_view_models::dfd_model(self);
        self.open_dfd_finding_query(
            &model,
            self.router.scene().dfd_selection(),
            self.router
                .scene()
                .dfd_focused()
                .then_some(self.router.scene().dfd_context_selection()),
        )
    }

    pub(crate) fn open_dfd_finding_query(
        &mut self,
        model: &crate::ui_view_models::DfdModel,
        selection: usize,
        context_row: Option<usize>,
    ) -> InputUpdate {
        let (target, paths) = match self.dfd_finding_paths(model, selection, context_row) {
            Ok(selection) => selection,
            Err(error) => return self.refuse_dfd_finding_query(error),
        };
        let expression = format!("files:{}", serde_json::json!(paths));
        let mut origin = self.capture_dfd_review_origin(target, expression.clone());
        origin.batch_config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .take()
            .map(Box::new);
        let update = self.reduce_hotkey_command(ShellCommand::FindingsFilter(expression));
        self.router.scene_mut().set_dfd_review_origin(origin);
        self.set_input_mode(crate::InputMode::Navigate);
        self.set_info_notice(
            "DFD findings",
            "Back returns to the diagram. Path matches span saved revisions.",
        );
        update
    }

    fn refuse_dfd_finding_query(&mut self, error: String) -> InputUpdate {
        if let Some(diagram) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_picker.as_mut())
            .and_then(|picker| picker.diagram.as_mut())
        {
            diagram.notice = Some(error.clone());
            self.log("DFD findings", error);
            return InputUpdate::handled();
        }
        self.set_warn_notice("DFD findings", error);
        InputUpdate::handled()
    }

    fn dfd_finding_paths(
        &self,
        model: &crate::ui_view_models::DfdModel,
        selection: usize,
        context_row: Option<usize>,
    ) -> Result<(PathBuf, Vec<String>), String> {
        if let Some(hint) = &model.empty_hint {
            return Err(hint.clone());
        }
        if model.link_state != crate::ui_view_models::DfdLinkState::Complete {
            return Err(
                "Inspect or rebuild linked context before opening findings at its evidence paths."
                    .into(),
            );
        }
        let target = self
            .target_owned()
            .ok_or("Select a target before opening saved findings.")?;
        let paths = evidence_finding_paths(
            &target,
            model.file_paths_for_selection(selection, context_row),
        );
        if paths.is_empty() {
            return Err("Select a component or context row with repository file evidence.".into());
        }
        Ok((target, paths))
    }

    fn capture_dfd_review_origin(&self, target: PathBuf, query: String) -> DfdReviewOrigin {
        DfdReviewOrigin {
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
            batch_config: None,
        }
    }

    pub(crate) fn dfd_review_return_is_available(&self) -> bool {
        self.router
            .scene()
            .dfd_review_origin()
            .is_some_and(|origin| self.dfd_review_origin_matches(origin))
    }

    pub(crate) fn dfd_path_query_is_active(&self) -> bool {
        self.dfd_review_return_is_available()
            && self
                .router
                .scene()
                .dfd_review_origin()
                .is_some_and(|origin| {
                    self.active_findings_filter().as_deref() == Some(origin.query.as_str())
                })
    }

    pub(super) fn restore_dfd_review_origin(&mut self) -> bool {
        if self.shell_view() != ShellView::Workbench {
            return false;
        }
        let Some(origin) = self.router.scene_mut().take_dfd_review_origin() else {
            return false;
        };
        if !self.dfd_review_origin_matches(&origin) {
            return false;
        }
        self.set_shell_view(origin.view);
        *self.router.workbench_mut() = origin.workbench;
        *self.router.findings_mut() = origin.findings;
        *self.router.navigation_mut() = origin.navigation;
        self.router.campaign_mut().batch_scan_config = origin.batch_config.map(|config| *config);
        self.router.set_overlay_origin(origin.overlay_origin);
        self.router
            .set_overlay_input_mode(origin.overlay_input_mode);
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
        true
    }

    fn dfd_review_origin_matches(&self, origin: &DfdReviewOrigin) -> bool {
        self.target() == Some(origin.target.as_path())
            && self.router.workbench().page() == Some(crate::app::WorkbenchPage::Review)
    }
}

fn evidence_finding_paths(target: &Path, paths: Vec<String>) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| relative_evidence_path(target, path))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn relative_evidence_path(target: &Path, evidence: &str) -> Option<String> {
    let value = evidence.replace('\\', "/");
    if value.contains("://") {
        return None;
    }
    let path = Path::new(&value);
    let relative = if path.is_absolute() {
        path.strip_prefix(target).ok()?
    } else {
        path
    };
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    let path = relative
        .components()
        .filter_map(normal_component)
        .collect::<Vec<_>>()
        .join("/");
    (!path.is_empty()).then_some(path)
}

fn normal_component<'a>(component: Component<'a>) -> Option<&'a str> {
    match component {
        Component::Normal(part) => part.to_str(),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
