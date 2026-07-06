use super::onboarding::file_picker_lines;
use super::*;
use crate::renderer::views::runs::run_diff_lines;
use crate::ShellView;

pub(crate) fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    primary_shell_view_lines(app, area)
        .or_else(|| threat_run_shell_view_lines(app, area))
        .or_else(|| system_shell_view_lines(app, area))
        .or_else(|| workspace_session_shell_view_lines(app, area))
        .unwrap_or_else(|| home_lines(app, area))
}

fn primary_shell_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    Some(match &app.shell_view {
        ShellView::Home => home_lines(app, area),
        ShellView::Catalog => catalog_view_lines(app, area),
        ShellView::Recommend => recommend_lines(app, area),
        ShellView::Module => module_lines(app, area),
        ShellView::ModuleRun => module_run_lines(app, area),
        ShellView::Workbench => workbench_lines(app, area),
        ShellView::Pwn => viewport_lines(
            pwn_lines(app, area),
            area.height,
            app.scroll_offset as usize,
        ),
        ShellView::Activity => viewport_lines(
            activity_lines(app, area),
            area.height,
            app.scroll_offset as usize,
        ),
        ShellView::Scene(page) => scene_page_lines(app, area, *page),
        _ => return None,
    })
}

fn threat_run_shell_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    Some(match &app.shell_view {
        ShellView::Tune => tune_lines(app, area),
        ShellView::Threat(view) => viewport_lines(
            threat_lines(app, area, *view),
            area.height,
            app.scroll_offset as usize,
        ),
        ShellView::ThreatEditor => threat_editor_lines(app, area),
        ShellView::PromptsEditor => prompts_lines(app, area),
        ShellView::ActorDetail(index) => actor_detail_lines(app, area, *index),
        ShellView::Runs => runs_lines(app, area),
        ShellView::RunDiff { left, right } => viewport_lines(
            run_diff_lines(app, area, left, right),
            area.height,
            app.scroll_offset as usize,
        ),
        ShellView::Replay(run_id) => replay_lines(app, area, run_id),
        ShellView::Trace(run_id) => trace_lines(app, area, run_id),
        ShellView::Patch(alias) => patch_lines(app, area, alias),
        _ => return None,
    })
}

fn system_shell_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    Some(match &app.shell_view {
        ShellView::Help => {
            viewport_lines(help_lines(app, area), area.height, app.help_route.scroll())
        }
        ShellView::Quickstart => viewport_lines(
            quickstart_lines(app, area),
            area.height,
            app.help_route.scroll(),
        ),
        ShellView::Logs => {
            viewport_lines(logs_lines(app, area), area.height, app.logs_route.scroll())
        }
        ShellView::Config => config_lines(app, area),
        ShellView::Health => viewport_lines(
            health_lines(app, area),
            area.height,
            app.scroll_offset as usize,
        ),
        ShellView::Tools => viewport_lines(
            tools_lines(app, area),
            area.height,
            app.tools_route.scroll(),
        ),
        ShellView::Auth => auth_lines(app, area),
        ShellView::Cost => cost_lines(app, area),
        ShellView::CommandPalette => command_palette_lines(app, area),
        ShellView::ModelPicker => model_picker_lines(app, area),
        ShellView::AuthMethodPicker(provider) => auth_method_picker_lines(app, area, provider),
        ShellView::TargetPicker => target_picker_lines(app, area),
        ShellView::PlanningPicker => planning_picker_lines(app, area),
        ShellView::FilePicker => file_picker_lines(app, area),
        _ => return None,
    })
}

fn workspace_session_shell_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    Some(match &app.shell_view {
        ShellView::Options(view) => options_lines(app, area, view),
        ShellView::SastTasks => sast_tasks_lines(app, area),
        ShellView::Context => context_lines(app, area),
        ShellView::ProjectModel => project_model_lines(app, area),
        ShellView::StrategyQueue => strategy_queue_lines(app, area),
        ShellView::Workspace => workspace_lines(app, area),
        ShellView::KnowledgeBase => viewport_lines(
            knowledge_base_lines(app, area),
            area.height,
            app.kb_route.scroll(),
        ),
        ShellView::FailureHandoff => failure_handoff_lines(app, area),
        ShellView::AgentChat => agent_chat_lines(app, area),
        ShellView::History => viewport_lines(
            history_lines(app, area),
            area.height,
            app.history_route.scroll(),
        ),
        ShellView::Story => story_lines(app, area),
        _ => return None,
    })
}

fn catalog_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let lines = catalog_lines(app, area);
    if app.catalog_route.is_expanded() {
        return viewport_lines(lines, area.height, app.modules_route.scroll());
    }
    lines
}
