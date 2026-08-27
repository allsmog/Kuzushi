use super::*;
use crate::scene3d::VizPage;

const AUTO_OPEN_INTERACTION_GRACE: std::time::Duration = std::time::Duration::from_secs(4);

/// Summary and DFD are operator guidance surfaces as well as artifact views.
/// Keep them reachable even before a threat model exists so the gallery can
/// explain what evidence is missing and how to generate it.
fn viz_page_is_permanent_surface(page: VizPage) -> bool {
    matches!(page, VizPage::Summary | VizPage::Dfd)
}

/// `has_content` is lazy: `viz_page_has_content` clones the cached DFD model,
/// and a permanent surface never needs the answer.
fn viz_page_is_available(page: VizPage, has_content: impl FnOnce() -> bool) -> bool {
    viz_page_is_permanent_surface(page) || has_content()
}

/// Map a completed tool to the gallery page that visualizes its artifact, if
/// any. Pure so the auto-open hooks stay testable. Matched exactly on the verbs
/// that actually *emit* the structured artifact the page draws — prereq steps
/// (`taint-iris-next:catalog`), read/info verbs (`threat-model:read`), and tools
/// that don't emit structured flows (`taint-iris-next:hunt` flattens its taint
/// path into finding text, unlike `taint-iris:hunt`) are intentionally absent so
/// auto-open never lands on an empty page.
pub(crate) fn viz_page_for_tool(tool_name: &str) -> Option<VizPage> {
    match tool_name {
        "taint-iris:hunt" => Some(VizPage::AttackPath),
        "exploit-chain:scan" => Some(VizPage::ExploitChain),
        "worklist:rank" => Some(VizPage::Worklist),
        _ => None,
    }
}

impl ShellApp {
    /// Open the gallery, keeping whatever page was last shown.
    pub fn open_scene(&mut self) {
        self.router.scene_mut().set_map_only(false);
        let page = self.available_viz_page(self.router.scene().page());
        self.open_scene_to_page(page);
    }

    /// Open the gallery focused on a specific page (manual nav and auto-open).
    pub fn open_scene_to_page(&mut self, page: VizPage) {
        self.router.scene_mut().set_map_only(false);
        let page = self.available_viz_page(page);
        self.open_scene_page(page);
    }

    /// Zoom the Map's selected projection without widening its tab set to
    /// unrelated Scan/Review visualizations.
    pub(crate) fn open_map_scene_to_page(&mut self, page: VizPage) {
        self.router.scene_mut().set_map_only(true);
        let page = self.available_map_viz_page(page);
        self.open_scene_page(page);
    }

    fn open_scene_page(&mut self, page: VizPage) {
        if !matches!(self.shell_view(), ShellView::Scene) {
            self.push_nav_history(self.shell_view());
        }
        self.router.scene_mut().set_page(page);
        self.set_shell_view(ShellView::Scene);
        let page_cycle = (self.active_viz_pages().len() > 1).then_some(" · Tab cycles pages");
        self.log(
            "scene",
            format!(
                "security-viz — {}{} · Esc/q returns",
                page.label(),
                page_cycle.unwrap_or_default()
            ),
        );
    }

    /// Auto-switch to a gallery page when its artifact lands, unless the
    /// operator opted out via `setg ui.auto_open_viz false`. Mirrors
    /// `auto_open_activity`.
    pub(crate) fn auto_open_viz_page(&mut self, page: VizPage) {
        if !self.ui().auto_open_viz() {
            return;
        }
        if self.run_focus_is_not_foreground() {
            self.log_scene_ready(page, "background run finished; view unchanged");
            return;
        }
        if self.defer_viz_until_run_focus_returns(page) {
            self.log_scene_ready(page, "opens after Run Focus returns");
            return;
        }
        self.open_or_log_scene_ready(page);
    }

    /// Open a deck that was deferred past a foreground Run Focus session.
    /// The completion's post-run refresh has just invalidated the view caches
    /// the deck renders from, so re-hydrate and re-check content before
    /// opening — never land the operator on an empty deck.
    pub(crate) fn open_deferred_viz_page(&mut self, page: VizPage) {
        // These are the threat-model-backed pages, which need the persisted doc
        // re-read before the content check. That they currently equal the
        // permanent set is a coincidence — do not fold this into
        // `viz_page_is_permanent_surface`.
        if matches!(page, VizPage::Summary | VizPage::Dfd) {
            self.hydrate_latest_threat_model_for_dfd();
        }
        if self.viz_page_has_content(page) {
            self.open_scene_to_page(page);
        } else {
            self.log_scene_ready(page, "artifact still hydrating; use `scene` to view");
        }
    }

    pub(super) fn hydrate_latest_threat_model_for_dfd(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let path = kuzushi_core::capabilities::persistent_threat_model_path(&target);
        self.invalidate_view_hydration();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_json_file(&path);
        self.hydrate_view_keys_blocking(
            &target,
            vec![crate::app::ViewHydrationKey::JsonFile { path }],
        );
    }

    fn run_focus_is_not_foreground(&self) -> bool {
        self.activity()
            .is_some_and(|session| session.run_focus_backgrounded)
            || (self.activity().is_some() && !matches!(self.shell_view(), ShellView::Activity))
    }

    fn defer_viz_until_run_focus_returns(&mut self, page: VizPage) -> bool {
        let Some(session) = self.activity_mut() else {
            return false;
        };
        let owned = !session.run_focus_backgrounded
            && session
                .run_focus_origin
                .is_some_and(|origin| origin.auto_return);
        if owned {
            session.run_focus_pending_viz = Some(page);
        }
        owned
    }

    fn open_or_log_scene_ready(&mut self, page: VizPage) {
        if matches!(self.shell_view(), ShellView::Activity) {
            self.log_scene_ready(page, "use `scene` to view");
            return;
        }
        if self.can_auto_open_viz_now() {
            self.open_scene_to_page(page);
        } else {
            self.log_scene_ready(page, "use `scene` to view");
        }
    }

    fn log_scene_ready(&mut self, page: VizPage, message: &str) {
        self.log(
            "scene",
            format!(
                "{} ready — {message}; setg ui.auto_open_viz false disables auto-open",
                page.label()
            ),
        );
    }

    fn can_auto_open_viz_now(&self) -> bool {
        if self
            .ui()
            .recent_operator_interaction(AUTO_OPEN_INTERACTION_GRACE)
        {
            return false;
        }
        !matches!(
            self.shell_view(),
            ShellView::Workbench
                | ShellView::TargetPicker
                | ShellView::PlanningPicker
                | ShellView::Setup
                | ShellView::PromptsEditor
                | ShellView::ThreatEditor
                | ShellView::Story
                | ShellView::FailureHandoff
                | ShellView::Trace
                | ShellView::Replay
        )
    }

    /// Whether `page` has a backing artifact worth showing. Guards auto-open so
    /// a tool run that produced nothing (clean scan, zero-flow hunt) doesn't
    /// yank the operator to an empty page that reads "run the tool".
    pub(crate) fn viz_page_has_content(&self, page: VizPage) -> bool {
        match page {
            VizPage::AttackPath => self.domain().taint_flow().is_some(),
            VizPage::ExploitChain => self.domain().has_exploit_chains(),
            VizPage::Summary => crate::ui_view_models::dfd_model(self).empty_hint.is_none(),
            VizPage::Dfd => crate::ui_view_models::dfd_model(self).empty_hint.is_none(),
            VizPage::EntryPoints => !crate::ui_view_models::entry_point_breakdown(self)
                .entries
                .is_empty(),
            VizPage::Components => {
                let stack = crate::ui_view_models::component_stack(self);
                !stack.sources.is_empty()
                    || !stack.languages.is_empty()
                    || !stack.build_systems.is_empty()
            }
            VizPage::Heatmap | VizPage::AttackSurface => !self.findings().is_empty(),
            VizPage::Worklist => !crate::ui_view_models::worklist_model(self).rows.is_empty(),
        }
    }

    /// Tabs that have real backing data, plus the permanent Summary and DFD
    /// guidance surfaces. Unavailable optional artifacts do not appear or
    /// consume Tab stops.
    pub(crate) fn available_viz_pages(&self) -> Vec<VizPage> {
        VizPage::ALL
            .into_iter()
            .filter(|page| viz_page_is_available(*page, || self.viz_page_has_content(*page)))
            .collect()
    }

    /// Map owns a smaller artifact vocabulary than the global gallery. Summary
    /// and DFD remain as guidance surfaces; every other tab is backed by a real
    /// persisted artifact.
    pub(crate) fn available_map_viz_pages(&self) -> Vec<VizPage> {
        [
            VizPage::Summary,
            VizPage::Dfd,
            VizPage::EntryPoints,
            VizPage::Components,
        ]
        .into_iter()
        .filter(|page| viz_page_is_available(*page, || self.viz_page_has_content(*page)))
        .collect()
    }

    pub(crate) fn active_viz_pages(&self) -> Vec<VizPage> {
        if self.router.scene().map_only() {
            self.available_map_viz_pages()
        } else {
            self.available_viz_pages()
        }
    }

    pub(crate) fn current_map_viz_page(&self) -> VizPage {
        self.available_map_viz_page(self.router.scene().page())
    }

    pub(crate) fn cycle_map_viz_page(&mut self, direction: i32) -> VizPage {
        let pages = self.available_map_viz_pages();
        let current = self.current_map_viz_page();
        let next = cycle_available_page(&pages, current, direction);
        self.router.scene_mut().set_page(next);
        next
    }

    pub(crate) fn cycle_scene_page(&mut self, direction: i32) -> VizPage {
        let pages = self.active_viz_pages();
        let next = cycle_available_page(&pages, self.router.scene().page(), direction);
        self.router.scene_mut().set_page(next);
        next
    }

    /// Resolve a requested landing page, redirecting empty optional pages to
    /// the always-available DFD. `Summary` and `Dfd` are permanent guidance
    /// surfaces. `Worklist` keeps its own empty `context:build → worklist:rank`
    /// guidance panel, so its explicit verb also lands before an artifact
    /// exists. Optional empty tabs still stay hidden from the rail.
    fn available_viz_page(&self, requested: VizPage) -> VizPage {
        if viz_page_is_permanent_surface(requested)
            || requested == VizPage::Worklist
            || self.viz_page_has_content(requested)
        {
            requested
        } else {
            VizPage::Dfd
        }
    }

    /// Fall back to Map's first available tab when the requested one has no
    /// artifact. Summary and Dfd are permanent members of the Map set and lead
    /// it, so that first entry is always Summary and the list is never empty —
    /// `VizPage::Dfd` is only the unreachable type-level floor.
    fn available_map_viz_page(&self, requested: VizPage) -> VizPage {
        let pages = self.available_map_viz_pages();
        if pages.contains(&requested) {
            return requested;
        }
        pages.first().copied().unwrap_or(VizPage::Dfd)
    }

    /// Switch to a specific gallery page and reflect it in the open view.
    pub fn set_scene_page(&mut self, page: VizPage) {
        let page = self.available_viz_page(page);
        self.router.scene_mut().set_page(page);
    }
}

fn cycle_available_page(pages: &[VizPage], current: VizPage, direction: i32) -> VizPage {
    let Some(index) = pages.iter().position(|page| *page == current) else {
        return VizPage::Dfd;
    };
    let offset = if direction >= 0 {
        1
    } else {
        pages.len().saturating_sub(1)
    };
    pages[(index + offset) % pages.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_and_dfd_are_reachable_without_backing_content() {
        assert!(viz_page_is_available(VizPage::Summary, || false));
        assert!(viz_page_is_available(VizPage::Dfd, || false));
    }

    #[test]
    fn permanent_surfaces_never_evaluate_the_content_probe() {
        for page in [VizPage::Summary, VizPage::Dfd] {
            assert!(
                viz_page_is_available(page, || panic!("{page:?} must short-circuit")),
                "{page:?}"
            );
        }
    }

    #[test]
    fn optional_viz_pages_still_require_backing_content() {
        for page in [
            VizPage::AttackSurface,
            VizPage::AttackPath,
            VizPage::EntryPoints,
            VizPage::Components,
            VizPage::Heatmap,
            VizPage::ExploitChain,
            VizPage::Worklist,
        ] {
            assert!(!viz_page_is_available(page, || false), "{page:?}");
            assert!(viz_page_is_available(page, || true), "{page:?}");
        }
    }
}
