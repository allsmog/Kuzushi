use super::onboarding::file_picker_lines;
use super::*;
use crate::renderer::views::runs::run_diff_lines;
use crate::ShellView;

pub(crate) fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    shell_view_lines_for(app, area, app.shell_view())
}

pub(crate) fn shell_view_lines_for(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Vec<Line<'static>> {
    primary_shell_view_lines(app, area, view)
        .or_else(|| threat_run_shell_view_lines(app, area, view))
        .or_else(|| system_shell_view_lines(app, area, view))
        .or_else(|| workspace_session_shell_view_lines(app, area, view))
        .unwrap_or_else(|| unwired_view_lines(app, area, view))
}

/// Honest fallback for a `ShellView` variant no router arm claims. Silently
/// showing Home here hid wiring bugs — the operator saw the wrong screen
/// with no indication anything was broken. The registry test iterates every
/// variant and fails on this sentinel.
fn unwired_view_lines(app: &ShellApp, area: Rect, view: ShellView) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        format!("⚠ {view:?} is not wired to a renderer — showing Home. Please report this."),
        theme::warn(),
    )];
    lines.extend(home_lines(app, area));
    lines
}

fn primary_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::Home => home_lines(app, area),
        ShellView::Catalog => catalog_view_lines(app, area),
        ShellView::Recommend => default_scrolled_lines(app, area, recommend_lines(app, area)),
        ShellView::Module => viewport_lines(
            module_lines(app, area),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::ModuleRun => module_run_lines(app, area),
        ShellView::Workbench => workbench_lines(app, area),
        ShellView::Setup => match app.router.setup().editor() {
            Some(crate::app::SetupEditor::Model) => model_picker_lines(app, area),
            Some(crate::app::SetupEditor::Credentials) => {
                auth_method_picker_lines(app, area, app.router.auth_picker().provider())
            }
            Some(crate::app::SetupEditor::Plan) => planning_picker_lines(app, area),
            Some(crate::app::SetupEditor::ThreatModel) => map_run_config_lines(app, area),
            _ => setup_lines(app, area),
        },
        ShellView::Report => report_lines(app, area),
        ShellView::Pwn => viewport_lines(
            pwn_lines(app, area),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::Activity => viewport_lines(
            activity_lines(app, area),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::Scene => scene_view_lines(app, area),
        _ => return None,
    })
}

fn scene_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    pinned_document_viewport_lines(
        scene_page_lines(app, area, app.router.scene().page()),
        area.height,
        default_scroll_offset(app),
        3,
    )
}

fn threat_run_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::Tune => tune_lines(app, area),
        // Pin the context strip + tab bar so long story/member lists scroll
        // beneath a stable header (Help/Tools pattern).
        ShellView::Threat => pinned_document_viewport_lines(
            threat_lines(app, area, app.router.threat().view()),
            area.height,
            default_scroll_offset(app),
            4,
        ),
        ShellView::ThreatEditor => threat_editor_lines(app, area),
        ShellView::PromptsEditor => prompts_lines(app, area),
        ShellView::ActorDetail => actor_detail_lines(app, area, app.router.actor_detail().index()),
        ShellView::Runs => default_scrolled_lines(app, area, runs_lines(app, area)),
        ShellView::Jobs => default_scrolled_lines(app, area, jobs_lines(app, area)),
        ShellView::Campaign => campaign_view_lines(app, area),
        ShellView::Coverage => default_scrolled_lines(app, area, coverage_lines(app, area)),
        ShellView::Relationships => super::relationships::relationship_lines(app, area),
        ShellView::Lessons => super::lessons::lesson_lines(app, area),
        ShellView::RunDiff => run_diff_view_lines(app, area),
        ShellView::Replay => default_scrolled_lines(
            app,
            area,
            replay_lines(app, area, app.router.replay().run_id()),
        ),
        ShellView::Trace => default_scrolled_lines(
            app,
            area,
            trace_lines(app, area, app.router.trace().run_id()),
        ),
        ShellView::Patch => patch_lines(app, area, app.router.patch().alias()),
        _ => return None,
    })
}

fn run_diff_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let route = app.router.run_diff();
    pinned_document_viewport_lines(
        run_diff_lines(app, area, route.left(), route.right()),
        area.height,
        default_scroll_offset(app),
        2,
    )
}

fn system_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    system_document_shell_view_lines(app, area, view)
        .or_else(|| system_overlay_shell_view_lines(app, area, view))
        .or_else(|| system_picker_shell_view_lines(app, area, view))
}

fn system_document_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::Help => pinned_document_viewport_lines(
            help_lines(app, area),
            area.height,
            app.router.help().scroll(),
            3,
        ),
        ShellView::Quickstart => viewport_lines(
            quickstart_lines(app, area),
            area.height,
            app.router.help().scroll(),
        ),
        ShellView::Logs => pinned_document_viewport_lines(
            logs_lines(app, area),
            area.height,
            app.router.logs().scroll(),
            logs_pinned_rows(app, area),
        ),
        ShellView::Config => default_scrolled_lines(app, area, config_lines(app, area)),
        ShellView::Permissions => permission_policy_view_lines(app, area),
        ShellView::Health => default_scrolled_lines(app, area, health_lines(app, area)),
        ShellView::Tools => pinned_document_viewport_lines(
            tools_lines(app, area),
            area.height,
            app.router.tools().scroll(),
            3,
        ),
        ShellView::Auth => auth_lines(app, area),
        ShellView::Cost => cost_lines(app, area),
        _ => return None,
    })
}

fn permission_policy_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    default_scrolled_lines(app, area, permission_policy_lines(app, area))
}

fn system_overlay_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::BootSplash => boot_splash_lines(app, area),
        ShellView::QuitConfirm => quit_confirm_lines(app, area),
        ShellView::ConfirmDialog => confirm_dialog_lines(app, area),
        ShellView::ThemePicker => theme_picker_lines(app, area),
        ShellView::Keymap => keymap_lines(app, area),
        ShellView::UpdateAvailable => update_available_lines(app, area),
        ShellView::Interruption => interruption_lines(app, area, app.router.interruption().view()),
        _ => return None,
    })
}

fn system_picker_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::CommandPalette => command_palette_lines(app, area),
        ShellView::TargetPicker => target_picker_lines(app, area),
        ShellView::PlanningPicker => planning_picker_lines(app, area),
        ShellView::FilePicker => file_picker_lines(app, area),
        _ => return None,
    })
}

fn workspace_session_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::Options => {
            default_scrolled_lines(app, area, options_lines(app, area, app.router.options()))
        }
        ShellView::SastTasks => default_scrolled_lines(app, area, sast_tasks_lines(app, area)),
        ShellView::Context => default_scrolled_lines(app, area, context_lines(app, area)),
        ShellView::ProjectModel => {
            default_scrolled_lines(app, area, project_model_lines(app, area))
        }
        ShellView::StrategyQueue => {
            default_scrolled_lines(app, area, strategy_queue_lines(app, area))
        }
        ShellView::Workspace => default_scrolled_lines(app, area, workspace_lines(app, area)),
        ShellView::KnowledgeBase => viewport_lines(
            knowledge_base_lines(app, area),
            area.height,
            app.router.kb().scroll(),
        ),
        ShellView::FailureHandoff => {
            default_scrolled_lines(app, area, failure_handoff_lines(app, area))
        }
        ShellView::History => viewport_lines(
            history_lines(app, area),
            area.height,
            app.router.history().scroll(),
        ),
        ShellView::Story => default_scrolled_lines(app, area, story_lines(app, area)),
        _ => return None,
    })
}

fn default_scroll_offset(app: &ShellApp) -> usize {
    app.router.default_scroll().offset() as usize
}

pub(super) fn default_scrolled_lines(
    app: &ShellApp,
    area: Rect,
    lines: Vec<Line<'static>>,
) -> Vec<Line<'static>> {
    viewport_lines(lines, area.height, default_scroll_offset(app))
}

fn catalog_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let lines = catalog_lines(app, area);
    if app.router.catalog().is_expanded() {
        return viewport_lines(lines, area.height, app.router.modules().scroll());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn default_scroll_reaches_the_tail_of_every_document_view_that_advertises_it() {
        let area = Rect::new(0, 0, 60, 4);
        for view in [
            ShellView::Recommend,
            ShellView::Runs,
            ShellView::Context,
            ShellView::FailureHandoff,
            ShellView::ProjectModel,
            ShellView::StrategyQueue,
            ShellView::Workspace,
            ShellView::Story,
        ] {
            let mut app = ShellApp::new(V2Config::default(), None);
            let top = rendered_text(shell_view_lines_for(&app, area, view));

            app.router.default_scroll_mut().tail();
            let tail_lines = shell_view_lines_for(&app, area, view);
            let tail = rendered_text(tail_lines.clone());

            assert_ne!(top, tail, "{view:?} ignored the default scroll offset");
            assert_eq!(tail_lines.len(), area.height as usize, "{view:?}");
        }
    }

    /// A1: the Threat view scrolls its document beneath a pinned header —
    /// context strip + blank + tab nav + blank stay visible at any offset.
    #[test]
    fn threat_view_keeps_the_tab_nav_pinned_while_scrolling() {
        let area = Rect::new(0, 0, 80, 6);
        let mut app = ShellApp::new(V2Config::default(), None);
        let document = threat_lines(&app, area, app.router.threat().view());
        assert!(
            document.len() > area.height as usize,
            "fixture document must overflow the viewport to exercise pinning"
        );

        app.router.default_scroll_mut().tail();
        let tail = rendered_text(shell_view_lines_for(&app, area, ShellView::Threat));
        assert!(
            tail.contains("1 STRIDE"),
            "tab nav must stay pinned under scroll:\n{tail}"
        );
    }

    fn rendered_text(lines: Vec<Line<'static>>) -> String {
        lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The wiring registry: EVERY `ShellView` variant must reach a real
    /// renderer arm. Before this test, an unwired variant silently rendered
    /// the Home screen; now it renders a loud sentinel and fails here.
    /// Adding a variant without a router arm fails this test automatically —
    /// `strum::EnumIter` iterates the enum, so there is no second list to
    /// keep in sync.
    #[test]
    fn every_shell_view_variant_is_wired_to_a_renderer() {
        use strum::IntoEnumIterator;
        let area = Rect::new(0, 0, 100, 24);
        for view in ShellView::iter() {
            let app = ShellApp::new(V2Config::default(), None);
            let text = rendered_text(shell_view_lines_for(&app, area, view));
            assert!(
                !text.contains("is not wired to a renderer"),
                "{view:?} has no renderer arm in shell_view_lines_for"
            );
            assert!(
                !text.trim().is_empty(),
                "{view:?} rendered an entirely blank screen"
            );
        }
    }
}
