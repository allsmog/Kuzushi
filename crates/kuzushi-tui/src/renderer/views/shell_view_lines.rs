use super::*;
use crate::ui_view_models::{
    shell_view_line_route, PrimaryViewRoute, ShellViewLineRoute, SystemViewRoute,
    ThreatAndRunViewRoute, WorkspaceSessionViewRoute,
};

pub(crate) fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match shell_view_line_route(app) {
        ShellViewLineRoute::Primary(route) => primary_view_lines(app, area, route),
        ShellViewLineRoute::ThreatAndRun(route) => threat_and_run_view_lines(app, area, route),
        ShellViewLineRoute::System(route) => system_view_lines(app, area, route),
        ShellViewLineRoute::WorkspaceAndSession(route) => {
            workspace_and_session_view_lines(app, area, route)
        }
    }
}

pub(crate) fn primary_view_lines(
    app: &ShellApp,
    area: Rect,
    route: PrimaryViewRoute<'_>,
) -> Vec<Line<'static>> {
    match route {
        PrimaryViewRoute::Home => home_lines(app, area),
        PrimaryViewRoute::Catalog { expanded, scroll } => {
            catalog_view_lines(app, area, expanded, scroll)
        }
        PrimaryViewRoute::Recommend => recommend_lines(app, area),
        PrimaryViewRoute::Module => module_lines(app, area),
        PrimaryViewRoute::ModuleRun => module_run_lines(app, area),
        PrimaryViewRoute::Findings => findings_lines(app, area),
        // Finding detail can run long (evidence, proof ladder, triage, patch
        // history); window it so `j/k/g/G` (which drive the route's scroll)
        // reveal the tail instead of it being clipped off the bottom.
        PrimaryViewRoute::Finding { scroll } => {
            viewport_lines(finding_detail_lines(app, area), area.height, scroll)
        }
        PrimaryViewRoute::Pwn { scroll } => {
            viewport_lines(pwn_lines(app, area), area.height, scroll)
        }
        PrimaryViewRoute::Activity { scroll } => {
            viewport_lines(activity_lines(app, area), area.height, scroll)
        }
        PrimaryViewRoute::Scene { page } => scene_page_lines(app, area, page),
        PrimaryViewRoute::ModelPicker => model_picker_lines(app, area),
        PrimaryViewRoute::AuthMethodPicker { provider } => {
            auth_method_picker_lines(app, area, provider)
        }
        PrimaryViewRoute::PlanningPicker => planning_picker_lines(app, area),
        PrimaryViewRoute::TargetPicker => target_picker_lines(app, area),
    }
}

fn catalog_view_lines(
    app: &ShellApp,
    area: Rect,
    expanded: bool,
    scroll: usize,
) -> Vec<Line<'static>> {
    let lines = catalog_lines(app, area);
    if expanded {
        return viewport_lines(lines, area.height, scroll);
    }
    lines
}

pub(crate) fn threat_and_run_view_lines(
    app: &ShellApp,
    area: Rect,
    route: ThreatAndRunViewRoute<'_>,
) -> Vec<Line<'static>> {
    match route {
        ThreatAndRunViewRoute::Tune => tune_lines(app, area),
        // STRIDE rollups and story lists run past the fold on short terminals;
        // window them so the existing scroll keys reach the tail.
        ThreatAndRunViewRoute::Threat { view, scroll } => {
            viewport_lines(threat_lines(app, area, view), area.height, scroll)
        }
        ThreatAndRunViewRoute::ThreatEditor => threat_editor_lines(app, area),
        ThreatAndRunViewRoute::PromptsEditor => prompts_lines(app, area),
        ThreatAndRunViewRoute::ActorDetail(index) => actor_detail_lines(app, area, index),
        ThreatAndRunViewRoute::Runs => runs_lines(app, area),
        ThreatAndRunViewRoute::Replay(run_id) => replay_lines(app, area, run_id),
        ThreatAndRunViewRoute::Trace(run_id) => trace_lines(app, area, run_id),
    }
}

pub(crate) fn system_view_lines(
    app: &ShellApp,
    area: Rect,
    route: SystemViewRoute<'_>,
) -> Vec<Line<'static>> {
    match route {
        SystemViewRoute::Help { scroll } => {
            viewport_lines(help_lines(app, area), area.height, scroll)
        }
        SystemViewRoute::Quickstart { scroll } => {
            viewport_lines(quickstart_lines(app, area), area.height, scroll)
        }
        SystemViewRoute::Logs { scroll } => {
            viewport_lines(logs_lines(app, area), area.height, scroll)
        }
        SystemViewRoute::Config => config_lines(app, area),
        SystemViewRoute::Tools { scroll } => {
            viewport_lines(tools_lines(app, area), area.height, scroll)
        }
        SystemViewRoute::Options(view) => options_lines(app, area, view),
        SystemViewRoute::SastTasks => sast_tasks_lines(app, area),
        SystemViewRoute::CommandPalette => command_palette_lines(app, area),
    }
}

pub(crate) fn workspace_and_session_view_lines(
    app: &ShellApp,
    area: Rect,
    route: WorkspaceSessionViewRoute<'_>,
) -> Vec<Line<'static>> {
    match route {
        WorkspaceSessionViewRoute::Context => context_lines(app, area),
        WorkspaceSessionViewRoute::Workspace => workspace_lines(app, area),
        WorkspaceSessionViewRoute::KnowledgeBase { scroll } => {
            viewport_lines(knowledge_base_lines(app, area), area.height, scroll)
        }
        WorkspaceSessionViewRoute::FailureHandoff => failure_handoff_lines(app, area),
        WorkspaceSessionViewRoute::AgentChat => agent_chat_lines(app, area),
        WorkspaceSessionViewRoute::History { scroll } => {
            viewport_lines(history_lines(app, area), area.height, scroll)
        }
        WorkspaceSessionViewRoute::Story => story_lines(app, area),
        WorkspaceSessionViewRoute::Auth => auth_lines(app, area),
        WorkspaceSessionViewRoute::Cost => cost_lines(app, area),
        WorkspaceSessionViewRoute::Patch(alias) => patch_lines(app, area, alias),
        WorkspaceSessionViewRoute::CatalogFallback => catalog_lines(app, area),
    }
}
