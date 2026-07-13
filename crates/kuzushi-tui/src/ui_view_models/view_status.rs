use super::{ShellApp, ShellView, ThreatView};

pub(crate) fn view_status_segment(app: &ShellApp) -> String {
    primary_view_status(app)
        .or_else(|| threat_view_status(app))
        .or_else(|| system_view_status(app))
        .unwrap_or_else(|| workspace_view_status(app))
}

fn primary_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view() {
        ShellView::Home => Some("home".to_string()),
        ShellView::Catalog => Some("capabilities".to_string()),
        ShellView::Recommend => Some("recommend".to_string()),
        ShellView::Module => Some(focused_or_default(app, "module")),
        ShellView::ModuleRun => Some(module_run_status(app)),
        ShellView::Workbench => Some("workbench".to_string()),
        ShellView::ModelPicker => Some("model-picker".to_string()),
        ShellView::TargetPicker => Some("target-picker".to_string()),
        ShellView::AuthMethodPicker => Some(format!(
            "auth-picker:{}",
            crate::app::auth_provider_label(app.router.auth_picker().provider())
        )),
        ShellView::PlanningPicker => Some("planning".to_string()),
        _ => None,
    }
}

fn threat_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view() {
        ShellView::Tune => Some("tune".to_string()),
        ShellView::Threat => Some(format!(
            "threats:{}",
            threat_view_slug(app.router.threat().view())
        )),
        ShellView::ThreatEditor => Some("threats:edit".to_string()),
        ShellView::PromptsEditor => Some("prompts".to_string()),
        ShellView::ActorDetail => Some(format!("actor:{}", app.router.actor_detail().index() + 1)),
        ShellView::Runs => Some("run-timeline".to_string()),
        ShellView::Jobs => Some("jobs".to_string()),
        ShellView::RunDiff => Some("run-diff".to_string()),
        ShellView::Replay => Some("replay".to_string()),
        ShellView::Trace => Some("trace".to_string()),
        ShellView::Activity => Some("activity".to_string()),
        ShellView::Scene => Some(format!("viz:{}", viz_page_slug(app.router.scene().page()))),
        _ => None,
    }
}

fn viz_page_slug(page: crate::scene3d::VizPage) -> &'static str {
    match page {
        crate::scene3d::VizPage::AttackSurface => "terrain",
        crate::scene3d::VizPage::AttackPath => "path",
        crate::scene3d::VizPage::Dfd => "dfd",
        crate::scene3d::VizPage::Heatmap => "heatmap",
        crate::scene3d::VizPage::ExploitChain => "chain",
    }
}

fn system_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view() {
        ShellView::Help => Some("help".to_string()),
        ShellView::Quickstart => Some("quickstart".to_string()),
        ShellView::Logs => Some("logs".to_string()),
        ShellView::Config => Some("config".to_string()),
        ShellView::Permissions => Some("permissions".to_string()),
        ShellView::Health => Some("health".to_string()),
        ShellView::Tools => Some("tools".to_string()),
        ShellView::BootSplash => Some("boot".to_string()),
        ShellView::QuitConfirm => Some("quit".to_string()),
        ShellView::ConfirmDialog => Some("confirm".to_string()),
        ShellView::ThemePicker => Some("theme".to_string()),
        ShellView::Keymap => Some("keymap".to_string()),
        ShellView::UpdateAvailable => Some("update".to_string()),
        ShellView::Interruption => Some(format!(
            "blocked:{}",
            interruption_slug(app.router.interruption().view())
        )),
        ShellView::CommandPalette => Some("palette".to_string()),
        ShellView::Options => Some(format!("options[{}]", app.router.options().tool_name)),
        ShellView::SastTasks => Some("tasks".to_string()),
        _ => None,
    }
}

fn workspace_view_status(app: &ShellApp) -> String {
    match &app.shell_view() {
        ShellView::Context => "context".to_string(),
        ShellView::ProjectModel => "project-model".to_string(),
        ShellView::StrategyQueue => "strategy-queue".to_string(),
        ShellView::Workspace => "workspace".to_string(),
        ShellView::KnowledgeBase => "kb".to_string(),
        ShellView::FailureHandoff => "failure-handoff".to_string(),
        ShellView::AgentChat => "agent".to_string(),
        ShellView::History => "history".to_string(),
        ShellView::Story => "story".to_string(),
        ShellView::Auth => "auth".to_string(),
        ShellView::Cost => "cost".to_string(),
        ShellView::Patch => format!("patch:{}", app.router.patch().alias()),
        ShellView::Pwn => "pwn".to_string(),
        _ => "modules".to_string(),
    }
}

fn focused_or_default(app: &ShellApp, default: &str) -> String {
    app.focused_module_owned()
        .unwrap_or_else(|| default.to_string())
}

fn module_run_status(app: &ShellApp) -> String {
    app.focused_module()
        .map(|module| format!("{module}/run"))
        .unwrap_or_else(|| "run".to_string())
}

fn threat_view_slug(view: ThreatView) -> &'static str {
    match view {
        ThreatView::Stride => "stride",
        ThreatView::Stories => "stories",
        ThreatView::Scope => "scope",
        ThreatView::Summary => "summary",
    }
}

fn interruption_slug(view: crate::app::InterruptionView) -> &'static str {
    match view {
        crate::app::InterruptionView::BudgetHardStop => "budget-hard-stop",
        crate::app::InterruptionView::BudgetStop => "budget-stop",
        crate::app::InterruptionView::NoBinary => "no-binary",
        crate::app::InterruptionView::NoModel => "no-model",
        crate::app::InterruptionView::NoPlugin => "no-plugin",
        crate::app::InterruptionView::NetworkDown => "network-down",
        crate::app::InterruptionView::RateLimited => "rate-limited",
    }
}

#[cfg(test)]
mod tests;
