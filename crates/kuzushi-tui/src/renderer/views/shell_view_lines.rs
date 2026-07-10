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
        ShellView::Module => module_lines(app, area),
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
        ShellView::Threat => viewport_lines(
            threat_lines(app, area, app.router.threat().view()),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::ThreatEditor => threat_editor_lines(app, area),
        ShellView::PromptsEditor => prompts_lines(app, area),
        ShellView::ActorDetail => actor_detail_lines(app, area, app.router.actor_detail().index()),
        ShellView::Runs => runs_lines(app, area),
        ShellView::Jobs => viewport_lines(
            jobs_lines(app, area),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::RunDiff => viewport_lines(
            run_diff_lines(
                app,
                area,
                app.router.run_diff().left(),
                app.router.run_diff().right(),
            ),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::Replay => replay_lines(app, area, app.router.replay().run_id()),
        ShellView::Trace => trace_lines(app, area, app.router.trace().run_id()),
        ShellView::Patch => patch_lines(app, area, app.router.patch().alias()),
        _ => return None,
    })
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
        ShellView::Help => viewport_lines(
            help_lines(app, area),
            area.height,
            app.router.help().scroll(),
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
        ShellView::Config => config_lines(app, area),
        ShellView::Health => viewport_lines(
            health_lines(app, area),
            area.height,
            default_scroll_offset(app),
        ),
        ShellView::Tools => viewport_lines(
            tools_lines(app, area),
            area.height,
            app.router.tools().scroll(),
        ),
        ShellView::Auth => auth_lines(app, area),
        ShellView::Cost => cost_lines(app, area),
        _ => return None,
    })
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
        ShellView::Options => options_lines(app, area, app.router.options()),
        ShellView::SastTasks => sast_tasks_lines(app, area),
        ShellView::Context => context_lines(app, area),
        ShellView::ProjectModel => project_model_lines(app, area),
        ShellView::StrategyQueue => strategy_queue_lines(app, area),
        ShellView::Workspace => workspace_lines(app, area),
        ShellView::KnowledgeBase => viewport_lines(
            knowledge_base_lines(app, area),
            area.height,
            app.router.kb().scroll(),
        ),
        ShellView::FailureHandoff => failure_handoff_lines(app, area),
        ShellView::AgentChat => agent_chat_lines(app, area),
        ShellView::History => viewport_lines(
            history_lines(app, area),
            area.height,
            app.router.history().scroll(),
        ),
        ShellView::Story => story_lines(app, area),
        _ => return None,
    })
}

fn default_scroll_offset(app: &ShellApp) -> usize {
    app.router.default_scroll().offset() as usize
}

fn catalog_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let lines = catalog_lines(app, area);
    if app.router.catalog().is_expanded() {
        return viewport_lines(lines, area.height, app.router.modules().scroll());
    }
    lines
}
