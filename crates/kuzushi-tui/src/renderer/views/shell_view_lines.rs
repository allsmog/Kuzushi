use super::*;

pub(crate) fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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

pub(crate) fn primary_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    match &app.shell_view {
        ShellView::Home => Some(home_lines(app, area)),
        ShellView::Catalog if app.catalog_expanded => Some(viewport_lines(
            catalog_lines(app, area),
            area.height,
            app.modules_scroll,
        )),
        ShellView::Catalog => Some(catalog_lines(app, area)),
        ShellView::Recommend => Some(recommend_lines(app, area)),
        ShellView::Module => Some(module_lines(app, area)),
        ShellView::ModuleRun => Some(module_run_lines(app, area)),
        ShellView::Findings => Some(findings_lines(app, area)),
        ShellView::Finding => Some(finding_detail_lines(app, area)),
        ShellView::Pwn => Some(viewport_lines(
            pwn_lines(app, area),
            area.height,
            app.scroll_offset as usize,
        )),
        ShellView::Activity => Some(viewport_lines(
            activity_lines(app, area),
            area.height,
            app.scroll_offset as usize,
        )),
        _ => None,
    }
}

pub(crate) fn threat_and_run_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
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

pub(crate) fn system_view_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
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

pub(crate) fn workspace_and_session_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match &app.shell_view {
        ShellView::Context => context_lines(app, area),
        ShellView::Workspace => workspace_lines(app, area),
        ShellView::KnowledgeBase => {
            viewport_lines(knowledge_base_lines(app, area), area.height, app.kb_scroll)
        }
        ShellView::FailureHandoff => failure_handoff_lines(app, area),
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
