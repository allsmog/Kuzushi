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
        .unwrap_or_else(|| home_lines(app, area))
}

fn primary_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::Home => home_lines(app, area),
        ShellView::Catalog => catalog_view_lines(app, area),
        ShellView::Recommend => recommend_lines(app, area),
        ShellView::Module => viewport_lines(
            module_lines(app, area),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::ModuleRun => module_run_lines(app, area),
        ShellView::Workbench => workbench_lines(app, area),
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
        ShellView::Scene => scene_page_lines(app, area, app.router.scene().page()),
        _ => return None,
    })
}

fn threat_run_shell_view_lines(
    app: &ShellApp,
    area: Rect,
    view: ShellView,
) -> Option<Vec<Line<'static>>> {
    Some(match view {
        ShellView::Tune => tune_lines(app, area),
        ShellView::Threat => default_scrolled_lines(
            app,
            area,
            threat_lines(app, area, app.router.threat().view()),
        ),
        ShellView::ThreatEditor => threat_editor_lines(app, area),
        ShellView::PromptsEditor => prompts_lines(app, area),
        ShellView::ActorDetail => actor_detail_lines(app, area, app.router.actor_detail().index()),
        ShellView::Runs => default_scrolled_lines(app, area, runs_lines(app, area)),
        ShellView::Jobs => default_scrolled_lines(app, area, jobs_lines(app, area)),
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
    default_scrolled_lines(
        app,
        area,
        run_diff_lines(app, area, route.left(), route.right()),
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
        ShellView::Logs => viewport_lines(
            logs_lines(app, area),
            area.height,
            app.router.logs().scroll(),
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
        ShellView::ModelPicker => model_picker_lines(app, area),
        ShellView::AuthMethodPicker => {
            auth_method_picker_lines(app, area, app.router.auth_picker().provider())
        }
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
        ShellView::FailureHandoff => failure_handoff_lines(app, area),
        ShellView::AgentChat => default_scrolled_lines(app, area, agent_chat_lines(app, area)),
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

fn default_scrolled_lines(
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
            ShellView::Runs,
            ShellView::Context,
            ShellView::ProjectModel,
            ShellView::StrategyQueue,
            ShellView::Workspace,
            ShellView::AgentChat,
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

    fn rendered_text(lines: Vec<Line<'static>>) -> String {
        lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}
