use crate::{OptionsView, ShellApp, ShellView, ThreatView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlainRenderMode<'a> {
    Options(&'a OptionsView),
    SastTasks,
    Context,
    ProjectModel,
    StrategyQueue,
    Workspace,
    KnowledgeBase,
    Config,
    Help,
    InteractiveOnly(PlainInteractiveOnlyModel),
    LineBased { include_context_strip: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainInteractiveOnlyModel {
    pub(crate) title: &'static str,
    pub(crate) next: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellViewLineRoute<'a> {
    Primary(PrimaryViewRoute<'a>),
    ThreatAndRun(ThreatAndRunViewRoute<'a>),
    System(SystemViewRoute<'a>),
    WorkspaceAndSession(WorkspaceSessionViewRoute<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryViewRoute<'a> {
    Home,
    Catalog { expanded: bool, scroll: usize },
    Recommend,
    Module,
    ModuleRun,
    Workbench,
    Pwn { scroll: usize },
    Activity { scroll: usize },
    Scene { page: crate::scene3d::VizPage },
    ModelPicker,
    AuthMethodPicker { provider: &'a str },
    PlanningPicker,
    TargetPicker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatAndRunViewRoute<'a> {
    Tune,
    Threat {
        view: ThreatView,
        scroll: usize,
    },
    ThreatEditor,
    PromptsEditor,
    ActorDetail(usize),
    Runs,
    RunDiff {
        left: &'a str,
        right: &'a str,
        scroll: usize,
    },
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
    CommandPalette,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceSessionViewRoute<'a> {
    Context,
    ProjectModel,
    StrategyQueue,
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

/// The Workbench command center owns the full body region with a frame-level
/// multi-pane split (SOURCE / CENTER / FINDINGS+DETAILS), like Activity and the
/// scene gallery. The shared line path is used only for plain/non-TTY output.
pub(crate) fn uses_workbench_frame(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::Workbench)
}

/// Frame-level gallery pages (3D terrain + the Canvas graph/tree diagrams) own
/// the full body region. Attack-path and heatmap use the shared line path.
pub(crate) fn uses_scene_frame(app: &ShellApp) -> bool {
    matches!(app.shell_view, ShellView::Scene(page) if page.is_frame_rendered())
}

pub(crate) fn plain_render_mode(app: &ShellApp) -> PlainRenderMode<'_> {
    if let Some(model) = interactive_only_plain_model(&app.shell_view) {
        return PlainRenderMode::InteractiveOnly(model);
    }

    match &app.shell_view {
        ShellView::Options(view) => PlainRenderMode::Options(view),
        ShellView::SastTasks => PlainRenderMode::SastTasks,
        ShellView::Context => PlainRenderMode::Context,
        ShellView::ProjectModel => PlainRenderMode::ProjectModel,
        ShellView::StrategyQueue => PlainRenderMode::StrategyQueue,
        ShellView::Workspace => PlainRenderMode::Workspace,
        ShellView::KnowledgeBase => PlainRenderMode::KnowledgeBase,
        ShellView::Config => PlainRenderMode::Config,
        ShellView::Help => PlainRenderMode::Help,
        ShellView::Workbench => PlainRenderMode::LineBased {
            include_context_strip: true,
        },
        _ => PlainRenderMode::LineBased {
            include_context_strip: false,
        },
    }
}

fn interactive_only_plain_model(view: &ShellView) -> Option<PlainInteractiveOnlyModel> {
    match view {
        ShellView::ModelPicker => Some(PlainInteractiveOnlyModel {
            title: "MODEL PICKER",
            next: "This picker needs an interactive terminal. Use `model <id>` or `config` in plain mode.".to_string(),
        }),
        ShellView::AuthMethodPicker(provider) => Some(PlainInteractiveOnlyModel {
                title: "AUTH PICKER",
                next: format!(
                    "This picker needs an interactive terminal. Use `auth login {provider}` or set credentials before relaunch."
                ),
            }),
        ShellView::TargetPicker => Some(PlainInteractiveOnlyModel {
            title: "TARGET PICKER",
            next: "This picker needs an interactive terminal. Use `target <path>` in plain mode.".to_string(),
        }),
        ShellView::PlanningPicker => Some(PlainInteractiveOnlyModel {
            title: "PLANNING PICKER",
            next: "This picker needs an interactive terminal. Use explicit `scan` or `run <tool>` commands in plain mode.".to_string(),
        }),
        ShellView::ThreatEditor => Some(PlainInteractiveOnlyModel {
            title: "THREAT EDITOR",
            next: "This editor needs an interactive terminal. Use `threats regen` or edit the threat model file directly.".to_string(),
        }),
        ShellView::PromptsEditor => Some(PlainInteractiveOnlyModel {
            title: "PROMPTS EDITOR",
            next: "This editor needs an interactive terminal. Use `prompt show <tool>` or edit `.kuzushi/prompts/` directly.".to_string(),
        }),
        ShellView::CommandPalette => Some(PlainInteractiveOnlyModel {
            title: "COMMAND PALETTE",
            next: "This palette needs an interactive terminal. Use `help <query>` in plain mode.".to_string(),
        }),
        _ => None,
    }
}

fn primary_view_route(app: &ShellApp) -> Option<PrimaryViewRoute<'_>> {
    match &app.shell_view {
        ShellView::Home => Some(PrimaryViewRoute::Home),
        ShellView::Catalog => Some(PrimaryViewRoute::Catalog {
            expanded: app.catalog_expanded,
            scroll: app.modules_scroll,
        }),
        ShellView::Recommend => Some(PrimaryViewRoute::Recommend),
        ShellView::Module => Some(PrimaryViewRoute::Module),
        ShellView::ModuleRun => Some(PrimaryViewRoute::ModuleRun),
        ShellView::Workbench => Some(PrimaryViewRoute::Workbench),
        ShellView::Pwn => Some(PrimaryViewRoute::Pwn {
            scroll: app.scroll_offset as usize,
        }),
        ShellView::Activity => Some(PrimaryViewRoute::Activity {
            scroll: app.scroll_offset as usize,
        }),
        ShellView::Scene(page) => Some(PrimaryViewRoute::Scene { page: *page }),
        ShellView::ModelPicker => Some(PrimaryViewRoute::ModelPicker),
        ShellView::AuthMethodPicker(provider) => Some(PrimaryViewRoute::AuthMethodPicker {
            provider: provider.as_str(),
        }),
        ShellView::PlanningPicker => Some(PrimaryViewRoute::PlanningPicker),
        ShellView::TargetPicker => Some(PrimaryViewRoute::TargetPicker),
        _ => None,
    }
}

fn threat_and_run_view_route(app: &ShellApp) -> Option<ThreatAndRunViewRoute<'_>> {
    match &app.shell_view {
        ShellView::Tune => Some(ThreatAndRunViewRoute::Tune),
        ShellView::Threat(view) => Some(ThreatAndRunViewRoute::Threat {
            view: *view,
            scroll: app.scroll_offset as usize,
        }),
        ShellView::ThreatEditor => Some(ThreatAndRunViewRoute::ThreatEditor),
        ShellView::PromptsEditor => Some(ThreatAndRunViewRoute::PromptsEditor),
        ShellView::ActorDetail(index) => Some(ThreatAndRunViewRoute::ActorDetail(*index)),
        ShellView::Runs => Some(ThreatAndRunViewRoute::Runs),
        ShellView::RunDiff { left, right } => Some(ThreatAndRunViewRoute::RunDiff {
            left,
            right,
            scroll: app.scroll_offset as usize,
        }),
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
        ShellView::CommandPalette => Some(SystemViewRoute::CommandPalette),
        _ => None,
    }
}

fn workspace_session_route(app: &ShellApp) -> WorkspaceSessionViewRoute<'_> {
    match &app.shell_view {
        ShellView::Context => WorkspaceSessionViewRoute::Context,
        ShellView::ProjectModel => WorkspaceSessionViewRoute::ProjectModel,
        ShellView::StrategyQueue => WorkspaceSessionViewRoute::StrategyQueue,
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

pub(crate) fn has_run_activity(app: &ShellApp) -> bool {
    app.scan.as_ref().is_some_and(|scan| scan.running) || app.running_tool_name().is_some()
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
