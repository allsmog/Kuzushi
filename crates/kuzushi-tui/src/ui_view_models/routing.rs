use super::{activity_view_model, ActivityViewModel};
use crate::{OptionsView, ShellApp, ShellView};

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
    Activity,
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
        RoutingMode::Shell => "shell route",
        RoutingMode::Module => "module route",
        RoutingMode::Agent => "agent route",
        RoutingMode::Plan => "plan route",
        RoutingMode::Run => "run route",
    }
    .to_string()
}

pub(crate) fn uses_activity_frame(app: &ShellApp) -> bool {
    matches!(app.shell_view(), ShellView::Activity)
        && matches!(activity_view_model(app), ActivityViewModel::Active(_))
}

/// The phase Workbench owns the full body region with a frame-level
/// multi-pane split (SOURCE / CENTER / FINDINGS+DETAILS), like Activity and the
/// scene gallery. The shared line path is used only for plain/non-TTY output.
pub(crate) fn uses_workbench_frame(app: &ShellApp) -> bool {
    matches!(app.shell_view(), ShellView::Workbench)
}

/// Frame-level gallery pages (3D terrain, graph/tree diagrams, and interactive
/// entry-point browser) own the full body region. Attack-path, Components, and
/// heatmap use the shared line path.
pub(crate) fn uses_scene_frame(app: &ShellApp) -> bool {
    matches!(app.shell_view(), ShellView::Scene) && app.router.scene().page().is_frame_rendered()
}

pub(crate) fn plain_render_mode(app: &ShellApp) -> PlainRenderMode<'_> {
    if app.auth_screen_snapshot().is_some() {
        return PlainRenderMode::LineBased {
            include_context_strip: false,
        };
    }

    if let Some(model) = interactive_only_plain_model(app) {
        return PlainRenderMode::InteractiveOnly(model);
    }

    match &app.shell_view() {
        ShellView::Activity => PlainRenderMode::Activity,
        ShellView::Options => PlainRenderMode::Options(app.router.options()),
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

fn interactive_only_plain_model(app: &ShellApp) -> Option<PlainInteractiveOnlyModel> {
    match &app.shell_view() {
        ShellView::TargetPicker => Some(PlainInteractiveOnlyModel {
            title: "TARGET PICKER",
            next: "This picker needs an interactive terminal. Use `target <path>` in plain mode.".to_string(),
        }),
        ShellView::FilePicker => Some(PlainInteractiveOnlyModel {
            title: "FILE PICKER",
            next: "This picker needs an interactive terminal. Use `attach <path>` in plain mode.".to_string(),
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
        _ => None,
    }
}

fn routing_state(app: &ShellApp) -> (bool, bool, bool, bool) {
    (
        has_run_activity(app),
        has_agent_activity(app),
        has_plan_activity(app),
        app.focused_module().is_some() && !matches!(app.shell_view(), ShellView::Catalog),
    )
}

pub(crate) fn has_run_activity(app: &ShellApp) -> bool {
    app.scan().is_some_and(|scan| scan.running) || app.running_tool_name().is_some()
}

fn has_agent_activity(app: &ShellApp) -> bool {
    app.agent_chat().is_some_and(|agent| agent.running)
}

fn has_plan_activity(app: &ShellApp) -> bool {
    app.planner_running() || app.engagement.has_pending_plan()
}

#[cfg(test)]
mod tests;
