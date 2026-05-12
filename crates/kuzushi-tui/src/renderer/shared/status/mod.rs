pub(in crate::renderer) use super::*;

pub(crate) fn scan_status(scan: &ScanPanelState) -> String {
    if scan.running && scan.abort_requested {
        "abort requested: waiting for subprocess".to_string()
    } else if scan.running {
        format!("running: {}", scan.stage)
    } else {
        scan.stage.clone()
    }
}

/// Cycle through braille spinner frames using `tick` as the index source.
/// Pass `app.spinner_phase as usize` so the animation advances on the event
/// loop's ~100ms extracted shell tick. Tests use `spinner_phase = 0` (frame `⠿`)
/// for determinism.
pub(crate) const SPINNER_FRAMES: &[&str] = &["⠿", "⠾", "⠷", "⠯", "⠟", "⠻"];

pub(crate) fn run_state_glyph(
    scan: Option<&ScanPanelState>,
    tool_running: bool,
    tick: usize,
) -> &'static str {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => "✗",
        Some(scan) if scan.running => SPINNER_FRAMES[tick % SPINNER_FRAMES.len()],
        Some(scan) if scan.error.is_some() => "✗",
        Some(_) => "✓",
        None if tool_running => SPINNER_FRAMES[tick % SPINNER_FRAMES.len()],
        None => "●",
    }
}

pub(crate) fn run_state_style(scan: Option<&ScanPanelState>, tool_running: bool) -> Style {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => theme::warn(),
        Some(scan) if scan.running => theme::warn(),
        Some(scan) if scan.error.is_some() => theme::danger(),
        Some(_) => theme::success(),
        None if tool_running => theme::warn(),
        None => theme::accent(),
    }
}

pub(crate) fn view_status_segment(app: &ShellApp) -> String {
    primary_view_status(app)
        .or_else(|| threat_view_status(app))
        .or_else(|| system_view_status(app))
        .unwrap_or_else(|| workspace_view_status(app))
}

pub(super) fn primary_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Catalog => Some(
            app.focused_module
                .clone()
                .unwrap_or_else(|| "catalog".to_string()),
        ),
        ShellView::Module => Some(
            app.focused_module
                .clone()
                .unwrap_or_else(|| "module".to_string()),
        ),
        ShellView::ModuleRun => Some(
            app.focused_module
                .as_ref()
                .map(|module| format!("{module}/run"))
                .unwrap_or_else(|| "run".to_string()),
        ),
        ShellView::Findings => Some("findings".to_string()),
        ShellView::Finding => Some("finding".to_string()),
        _ => None,
    }
}

pub(super) fn threat_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Tune => Some("tune".to_string()),
        ShellView::Threat(view) => Some(format!(
            "threats:{}",
            match view {
                ThreatView::Dfd => "dfd",
                ThreatView::Stride => "stride",
                ThreatView::Stories => "stories",
                ThreatView::Scope => "scope",
                ThreatView::Summary => "summary",
            }
        )),
        ShellView::ThreatEditor => Some("threats:edit".to_string()),
        ShellView::PromptsEditor => Some("prompts".to_string()),
        ShellView::ActorDetail(index) => Some(format!("actor:{}", index + 1)),
        ShellView::Runs => Some("runs".to_string()),
        ShellView::Replay(_) => Some("replay".to_string()),
        ShellView::Trace(_) => Some("trace".to_string()),
        ShellView::Activity => Some("activity".to_string()),
        _ => None,
    }
}

pub(super) fn system_view_status(app: &ShellApp) -> Option<String> {
    match &app.shell_view {
        ShellView::Help => Some("help".to_string()),
        ShellView::Quickstart => Some("quickstart".to_string()),
        ShellView::Config => Some("config".to_string()),
        ShellView::Tools => Some("tools".to_string()),
        ShellView::Options(view) => Some(format!("options[{}]", view.tool_name)),
        ShellView::SastTasks => Some("tasks".to_string()),
        _ => None,
    }
}

pub(super) fn workspace_view_status(app: &ShellApp) -> String {
    match &app.shell_view {
        ShellView::Context => "context".to_string(),
        ShellView::Workspace => "workspace".to_string(),
        ShellView::KnowledgeBase => "kb".to_string(),
        ShellView::AgentChat => "agent".to_string(),
        ShellView::History => "history".to_string(),
        ShellView::Story => "story".to_string(),
        ShellView::Auth => "auth".to_string(),
        ShellView::Cost => "cost".to_string(),
        ShellView::Patch(alias) => format!("patch:{alias}"),
        ShellView::Pwn => "pwn".to_string(),
        _ => "catalog".to_string(),
    }
}
