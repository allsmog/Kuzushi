use crate::{OptionsView, ShellApp, ShellView, ThreatView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlainRenderMode<'a> {
    Options(&'a OptionsView),
    SastTasks,
    Context,
    Workspace,
    KnowledgeBase,
    Config,
    Help,
    LineBased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellViewLineRoute<'a> {
    Primary(PrimaryViewRoute),
    ThreatAndRun(ThreatAndRunViewRoute<'a>),
    System(SystemViewRoute<'a>),
    WorkspaceAndSession(WorkspaceSessionViewRoute<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryViewRoute {
    Home,
    Catalog { expanded: bool, scroll: usize },
    Recommend,
    Module,
    ModuleRun,
    Findings,
    Finding,
    Pwn { scroll: usize },
    Activity { scroll: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatAndRunViewRoute<'a> {
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    PromptsEditor,
    ActorDetail(usize),
    Runs,
    Replay(&'a str),
    Trace(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemViewRoute<'a> {
    Help { scroll: usize },
    Quickstart { scroll: usize },
    Logs { scroll: usize },
    Config,
    Tools { scroll: usize },
    Options(&'a OptionsView),
    SastTasks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceSessionViewRoute<'a> {
    Context,
    Workspace,
    KnowledgeBase { scroll: usize },
    FailureHandoff,
    AgentChat,
    History { scroll: usize },
    Story,
    Auth,
    Cost,
    Patch(&'a str),
    CatalogFallback,
}

pub(crate) fn routing_mode(app: &ShellApp) -> RoutingMode {
    match routing_state(app) {
        (true, _, _, _) => RoutingMode::Run,
        (_, true, _, _) => RoutingMode::Agent,
        (_, _, true, _) => RoutingMode::Plan,
        (_, _, _, true) => RoutingMode::Module,
        _ => RoutingMode::Shell,
    }
}

pub(crate) fn routing_mode_segment(app: &ShellApp) -> String {
    match routing_mode(app) {
        RoutingMode::Shell => "mode:shell",
        RoutingMode::Module => "mode:module",
        RoutingMode::Agent => "mode:agent",
        RoutingMode::Plan => "mode:plan",
        RoutingMode::Run => "mode:run",
    }
    .to_string()
}

pub(crate) fn shell_view_line_route(app: &ShellApp) -> ShellViewLineRoute<'_> {
    primary_view_route(app)
        .map(ShellViewLineRoute::Primary)
        .or_else(|| threat_and_run_view_route(app).map(ShellViewLineRoute::ThreatAndRun))
        .or_else(|| system_view_route(app).map(ShellViewLineRoute::System))
        .unwrap_or_else(|| ShellViewLineRoute::WorkspaceAndSession(workspace_session_route(app)))
}

pub(crate) fn uses_activity_frame(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::Activity)
}

pub(crate) fn plain_render_mode(app: &ShellApp) -> PlainRenderMode<'_> {
    match &app.shell_view {
        ShellView::Options(view) => PlainRenderMode::Options(view),
        ShellView::SastTasks => PlainRenderMode::SastTasks,
        ShellView::Context => PlainRenderMode::Context,
        ShellView::Workspace => PlainRenderMode::Workspace,
        ShellView::KnowledgeBase => PlainRenderMode::KnowledgeBase,
        ShellView::Config => PlainRenderMode::Config,
        ShellView::Help => PlainRenderMode::Help,
        _ => PlainRenderMode::LineBased,
    }
}

fn primary_view_route(app: &ShellApp) -> Option<PrimaryViewRoute> {
    match &app.shell_view {
        ShellView::Home => Some(PrimaryViewRoute::Home),
        ShellView::Catalog => Some(PrimaryViewRoute::Catalog {
            expanded: app.catalog_expanded,
            scroll: app.modules_scroll,
        }),
        ShellView::Recommend => Some(PrimaryViewRoute::Recommend),
        ShellView::Module => Some(PrimaryViewRoute::Module),
        ShellView::ModuleRun => Some(PrimaryViewRoute::ModuleRun),
        ShellView::Findings => Some(PrimaryViewRoute::Findings),
        ShellView::Finding => Some(PrimaryViewRoute::Finding),
        ShellView::Pwn => Some(PrimaryViewRoute::Pwn {
            scroll: app.scroll_offset as usize,
        }),
        ShellView::Activity => Some(PrimaryViewRoute::Activity {
            scroll: app.scroll_offset as usize,
        }),
        _ => None,
    }
}

fn threat_and_run_view_route(app: &ShellApp) -> Option<ThreatAndRunViewRoute<'_>> {
    match &app.shell_view {
        ShellView::Tune => Some(ThreatAndRunViewRoute::Tune),
        ShellView::Threat(view) => Some(ThreatAndRunViewRoute::Threat(*view)),
        ShellView::ThreatEditor => Some(ThreatAndRunViewRoute::ThreatEditor),
        ShellView::PromptsEditor => Some(ThreatAndRunViewRoute::PromptsEditor),
        ShellView::ActorDetail(index) => Some(ThreatAndRunViewRoute::ActorDetail(*index)),
        ShellView::Runs => Some(ThreatAndRunViewRoute::Runs),
        ShellView::Replay(run_id) => Some(ThreatAndRunViewRoute::Replay(run_id)),
        ShellView::Trace(run_id) => Some(ThreatAndRunViewRoute::Trace(run_id)),
        _ => None,
    }
}

fn system_view_route(app: &ShellApp) -> Option<SystemViewRoute<'_>> {
    match &app.shell_view {
        ShellView::Help => Some(SystemViewRoute::Help {
            scroll: app.help_scroll,
        }),
        ShellView::Quickstart => Some(SystemViewRoute::Quickstart {
            scroll: app.help_scroll,
        }),
        ShellView::Logs => Some(SystemViewRoute::Logs {
            scroll: app.logs_scroll,
        }),
        ShellView::Config => Some(SystemViewRoute::Config),
        ShellView::Tools => Some(SystemViewRoute::Tools {
            scroll: app.tools_scroll,
        }),
        ShellView::Options(view) => Some(SystemViewRoute::Options(view)),
        ShellView::SastTasks => Some(SystemViewRoute::SastTasks),
        _ => None,
    }
}

fn workspace_session_route(app: &ShellApp) -> WorkspaceSessionViewRoute<'_> {
    match &app.shell_view {
        ShellView::Context => WorkspaceSessionViewRoute::Context,
        ShellView::Workspace => WorkspaceSessionViewRoute::Workspace,
        ShellView::KnowledgeBase => WorkspaceSessionViewRoute::KnowledgeBase {
            scroll: app.kb_scroll,
        },
        ShellView::FailureHandoff => WorkspaceSessionViewRoute::FailureHandoff,
        ShellView::AgentChat => WorkspaceSessionViewRoute::AgentChat,
        ShellView::History => WorkspaceSessionViewRoute::History {
            scroll: app.history_scroll,
        },
        ShellView::Story => WorkspaceSessionViewRoute::Story,
        ShellView::Auth => WorkspaceSessionViewRoute::Auth,
        ShellView::Cost => WorkspaceSessionViewRoute::Cost,
        ShellView::Patch(alias) => WorkspaceSessionViewRoute::Patch(alias),
        _ => WorkspaceSessionViewRoute::CatalogFallback,
    }
}

fn routing_state(app: &ShellApp) -> (bool, bool, bool, bool) {
    (
        has_run_activity(app),
        has_agent_activity(app),
        has_plan_activity(app),
        app.focused_module.is_some(),
    )
}

fn has_run_activity(app: &ShellApp) -> bool {
    app.scan.as_ref().is_some_and(|scan| scan.running)
        || app.running_tool_name().is_some()
        || matches!(app.shell_view, ShellView::ModuleRun)
}

fn has_agent_activity(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::AgentChat)
        || app.agent_chat.as_ref().is_some_and(|agent| agent.running)
}

fn has_plan_activity(app: &ShellApp) -> bool {
    app.planner_running || app.pending_plan.is_some()
}

#[cfg(test)]
mod tests;
