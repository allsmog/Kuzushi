use super::*;

mod catalog;
mod chat;
mod editor;
mod findings;
mod help;
mod module;
mod options;
mod patch;
mod runs;
mod system;
mod threat;
mod workspace;

pub(super) use catalog::*;
pub(super) use chat::*;
pub(super) use editor::*;
pub(super) use findings::*;
pub(super) use help::*;
pub(super) use module::*;
pub(super) use options::*;
pub(super) use patch::*;
pub(super) use runs::*;
pub(super) use system::*;
pub(super) use threat::*;
pub(super) use workspace::*;

pub(super) fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(lines) = primary_view_lines(app, area) {
        return lines;
    }
    if let Some(lines) = threat_and_run_view_lines(app, area) {
        return lines;
    }
    if let Some(lines) = system_view_lines(app, area) {
        return lines;
    }
    workspace_and_session_view_lines(app, area)
}

fn primary_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    match &app.shell_view {
        ShellView::Catalog if app.catalog_expanded => Some(viewport_lines(
            catalog_lines(app, area),
            area.height,
            app.modules_scroll,
        )),
        ShellView::Catalog => Some(catalog_lines(app, area)),
        ShellView::Module => Some(module_lines(app, area)),
        ShellView::ModuleRun => Some(module_run_lines(app, area)),
        ShellView::Findings => Some(findings_lines(app, area)),
        ShellView::Finding => Some(finding_detail_lines(app, area)),
        _ => None,
    }
}

fn threat_and_run_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    match &app.shell_view {
        ShellView::Tune => Some(tune_lines(app, area)),
        ShellView::Threat(view) => Some(threat_lines(app, area, *view)),
        ShellView::ThreatEditor => Some(threat_editor_lines(app, area)),
        ShellView::PromptsEditor => Some(prompts_lines(app, area)),
        ShellView::ActorDetail(index) => Some(actor_detail_lines(app, area, *index)),
        ShellView::Runs => Some(runs_lines(app, area)),
        ShellView::Replay(run_id) => Some(replay_lines(app, area, run_id)),
        ShellView::Trace(run_id) => Some(trace_lines(app, area, run_id)),
        _ => None,
    }
}

fn system_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    match &app.shell_view {
        ShellView::Help => Some(viewport_lines(
            help_lines(app, area),
            area.height,
            app.help_scroll,
        )),
        ShellView::Quickstart => Some(viewport_lines(
            quickstart_lines(app, area),
            area.height,
            app.help_scroll,
        )),
        ShellView::Config => Some(config_lines(app, area)),
        ShellView::Tools => Some(viewport_lines(
            tools_lines(app, area),
            area.height,
            app.tools_scroll,
        )),
        ShellView::Options(view) => Some(options_lines(app, area, view)),
        ShellView::SastTasks => Some(sast_tasks_lines(app, area)),
        _ => None,
    }
}

fn workspace_and_session_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match &app.shell_view {
        ShellView::Context => context_lines(app, area),
        ShellView::Workspace => workspace_lines(app, area),
        ShellView::KnowledgeBase => {
            viewport_lines(knowledge_base_lines(app, area), area.height, app.kb_scroll)
        }
        ShellView::AgentChat => agent_chat_lines(app, area),
        ShellView::History => {
            viewport_lines(history_lines(app, area), area.height, app.history_scroll)
        }
        ShellView::Story => story_lines(app, area),
        ShellView::Auth => auth_lines(app, area),
        ShellView::Cost => cost_lines(app, area),
        ShellView::Patch(alias) => patch_lines(app, area, alias),
        _ => catalog_lines(app, area),
    }
}

pub(super) fn viewport_lines(
    lines: Vec<Line<'static>>,
    visible_height: u16,
    scroll: usize,
) -> Vec<Line<'static>> {
    let visible = visible_height as usize;
    if visible == 0 {
        return Vec::new();
    }
    if lines.len() <= visible {
        return lines;
    }
    let start = scroll.min(lines.len().saturating_sub(visible));
    lines.into_iter().skip(start).take(visible).collect()
}

pub(super) fn viewport_start_for_cursor(
    total_rows: usize,
    visible_rows: usize,
    cursor: usize,
) -> usize {
    if total_rows <= visible_rows || visible_rows == 0 {
        return 0;
    }
    let max_start = total_rows.saturating_sub(visible_rows);
    let margin = visible_rows.saturating_sub(1) / 2;
    cursor.saturating_sub(margin).min(max_start)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

pub(super) fn routing_mode(app: &ShellApp) -> RoutingMode {
    if app.scan.as_ref().is_some_and(|scan| scan.running)
        || app.running_tool_name().is_some()
        || matches!(app.shell_view, ShellView::ModuleRun)
    {
        RoutingMode::Run
    } else if matches!(app.shell_view, ShellView::AgentChat)
        || app.agent_chat.as_ref().is_some_and(|agent| agent.running)
    {
        RoutingMode::Agent
    } else if app.planner_running || app.pending_plan.is_some() {
        RoutingMode::Plan
    } else if app.focused_module.is_some() {
        RoutingMode::Module
    } else {
        RoutingMode::Shell
    }
}

pub(super) fn routing_mode_segment(app: &ShellApp) -> String {
    match routing_mode(app) {
        RoutingMode::Shell => "mode:shell",
        RoutingMode::Module => "mode:module",
        RoutingMode::Agent => "mode:agent",
        RoutingMode::Plan => "mode:plan",
        RoutingMode::Run => "mode:run",
    }
    .to_string()
}
