use super::{ShellApp, ShellView, ThreatView};

pub(crate) fn view_status_segment(app: &ShellApp) -> String {
    primary_view_status(app)
        .or_else(|| threat_view_status(app))
        .or_else(|| system_view_status(app))
        .unwrap_or_else(|| workspace_view_status(app))
}

fn primary_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Home => Some("home".to_string()),
        ShellView::Catalog => Some(focused_or_default(app, "modules")),
        ShellView::Recommend => Some("recommend".to_string()),
        ShellView::Module => Some(focused_or_default(app, "module")),
        ShellView::ModuleRun => Some(module_run_status(app)),
        ShellView::Findings => Some("findings".to_string()),
        ShellView::Finding => Some("finding".to_string()),
        ShellView::ModelPicker => Some("model-picker".to_string()),
        ShellView::TargetPicker => Some("target-picker".to_string()),
        ShellView::AuthMethodPicker(provider) => Some(format!("auth-picker:{provider}")),
        ShellView::PlanningPicker => Some("planning".to_string()),
        _ => None,
    }
}

fn threat_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Tune => Some("tune".to_string()),
        ShellView::Threat(view) => Some(format!("threats:{}", threat_view_slug(*view))),
        ShellView::ThreatEditor => Some("threats:edit".to_string()),
        ShellView::PromptsEditor => Some("prompts".to_string()),
        ShellView::ActorDetail(index) => Some(format!("actor:{}", index + 1)),
        ShellView::Runs => Some("run-timeline".to_string()),
        ShellView::Replay(_) => Some("replay".to_string()),
        ShellView::Trace(_) => Some("trace".to_string()),
        ShellView::Activity => Some("activity".to_string()),
        _ => None,
    }
}

fn system_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Help => Some("help".to_string()),
        ShellView::Quickstart => Some("quickstart".to_string()),
        ShellView::Logs => Some("logs".to_string()),
        ShellView::Config => Some("config".to_string()),
        ShellView::Tools => Some("tools".to_string()),
        ShellView::Options(view) => Some(format!("options[{}]", view.tool_name)),
        ShellView::SastTasks => Some("tasks".to_string()),
        _ => None,
    }
}

fn workspace_view_status(app: &ShellApp) -> String {
    match &app.shell_view {
        ShellView::Context => "context".to_string(),
        ShellView::Workspace => "workspace".to_string(),
        ShellView::KnowledgeBase => "kb".to_string(),
        ShellView::FailureHandoff => "failure-handoff".to_string(),
        ShellView::AgentChat => "agent".to_string(),
        ShellView::History => "history".to_string(),
        ShellView::Story => "story".to_string(),
        ShellView::Auth => "auth".to_string(),
        ShellView::Cost => "cost".to_string(),
        ShellView::Patch(alias) => format!("patch:{alias}"),
        ShellView::Pwn => "pwn".to_string(),
        _ => "modules".to_string(),
    }
}

fn focused_or_default(app: &ShellApp, default: &str) -> String {
    app.focused_module
        .clone()
        .unwrap_or_else(|| default.to_string())
}

fn module_run_status(app: &ShellApp) -> String {
    app.focused_module
        .as_ref()
        .map(|module| format!("{module}/run"))
        .unwrap_or_else(|| "run".to_string())
}

fn threat_view_slug(view: ThreatView) -> &'static str {
    match view {
        ThreatView::Dfd => "dfd",
        ThreatView::Stride => "stride",
        ThreatView::Stories => "stories",
        ThreatView::Scope => "scope",
        ThreatView::Summary => "summary",
    }
}

#[cfg(test)]
mod tests;
