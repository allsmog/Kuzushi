use std::collections::BTreeMap;

use kuzushi_core::modules::{ModuleKind, OptionSpec, OptionType};
use kuzushi_core::{
    sorted_finding_aliases, stable_finding_alias, AttachmentKind, Finding, Severity,
    SUPPORTED_ATTACHMENT_MODULES,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Modifier, Span, Style};
use ratatui::widgets::Paragraph;

use crate::app::{ScanPanelState, ShellApp, ShellView, ThreatView};
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
use crate::theme;

mod plain;

pub use plain::{render_plain_app, render_plain_command_result};

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let prompt_height = 1;
    let transcript_height = if matches!(app.shell_view, ShellView::ModuleRun) {
        0
    } else if area.height >= 12 {
        2
    } else {
        0
    };
    let keybind_height = if area.height >= 8 { 2 } else { 0 };
    let status_height = if area.height >= 6 { 1 } else { 0 };
    let throttle_height = if app.advisory.throttle.is_some() && area.height >= 5 {
        1
    } else {
        0
    };
    let budget_height = if app.is_budget_halted() && area.height >= 5 {
        2
    } else {
        0
    };
    let plan_height = plan_card_height(app, area);
    let threat_patch_height = threat_patch_card_height(app, area);
    let fixed_height = prompt_height
        + transcript_height
        + keybind_height
        + status_height
        + throttle_height
        + budget_height
        + plan_height
        + threat_patch_height;
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let view_area = Rect {
        height: max_view_height,
        ..area
    };
    let view_lines = shell_view_lines(app, view_area);
    let view_height = (view_lines.len() as u16).clamp(1, max_view_height);

    let mut constraints = vec![Constraint::Length(view_height), Constraint::Min(0)];
    if throttle_height > 0 {
        constraints.push(Constraint::Length(throttle_height));
    }
    if status_height > 0 {
        constraints.push(Constraint::Length(status_height));
    }
    if keybind_height > 0 {
        constraints.push(Constraint::Length(keybind_height));
    }
    if budget_height > 0 {
        constraints.push(Constraint::Length(budget_height));
    }
    if plan_height > 0 {
        constraints.push(Constraint::Length(plan_height));
    }
    if threat_patch_height > 0 {
        constraints.push(Constraint::Length(threat_patch_height));
    }
    if transcript_height > 0 {
        constraints.push(Constraint::Length(transcript_height));
    }
    constraints.push(Constraint::Length(prompt_height));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut index = 0;
    render_lines(frame, chunks[index], view_lines);
    index += 1;
    index += 1;

    if throttle_height > 0 {
        render_throttle_banner(frame, chunks[index], app);
        index += 1;
    }
    if status_height > 0 {
        render_status_footer(frame, chunks[index], app);
        index += 1;
    }
    if keybind_height > 0 {
        render_keybind_footer(frame, chunks[index], app);
        index += 1;
    }
    if budget_height > 0 {
        render_cost_cap_halt(frame, chunks[index], app);
        index += 1;
    }
    if plan_height > 0 {
        render_plan_card(frame, chunks[index], app);
        index += 1;
    }
    if threat_patch_height > 0 {
        render_threat_patch_card(frame, chunks[index], app);
        index += 1;
    }
    if transcript_height > 0 {
        render_transcript(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
}

fn threat_patch_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(patch) = &app.pending_threat_patch else {
        return 0;
    };
    let body = (patch.unsupported.len() + 1) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}

fn render_threat_patch_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(patch) = app.pending_threat_patch.as_ref() else {
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ THREAT PATCH · goal: {}", patch.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(
            &format!("  summary: {}", patch.summary),
            area.width as usize,
        ),
        theme::primary(),
    ));
    let key_count = match &patch.patch {
        serde_json::Value::Object(map) => map.len(),
        _ => 0,
    };
    lines.push(Line::styled(
        fit(
            &format!("  patch: {key_count} top-level key(s)"),
            area.width as usize,
        ),
        theme::success(),
    ));
    for note in &patch.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    lines.push(Line::styled(
        fit("/threats apply   /threats reject", area.width as usize),
        theme::label(),
    ));
    render_lines(frame, area, lines);
}

fn plan_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(plan) = &app.pending_plan else {
        return 0;
    };
    let body = (plan.changes.len() + plan.unsupported.len()) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}

fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match &app.shell_view {
        ShellView::Catalog if app.catalog_expanded => {
            viewport_lines(catalog_lines(app, area), area.height, app.modules_scroll)
        }
        ShellView::Catalog => catalog_lines(app, area),
        ShellView::Module => module_lines(app, area),
        ShellView::ModuleRun => module_run_lines(app, area),
        ShellView::Findings => findings_lines(app, area),
        ShellView::Finding => finding_detail_lines(app, area),
        ShellView::Tune => tune_lines(app, area),
        ShellView::Threat(view) => threat_lines(app, area, *view),
        ShellView::ThreatEditor => threat_editor_lines(app, area),
        ShellView::PromptsEditor => prompts_lines(app, area),
        ShellView::ActorDetail(index) => actor_detail_lines(app, area, *index),
        ShellView::Runs => runs_lines(app, area),
        ShellView::Replay(run_id) => replay_lines(app, area, run_id),
        ShellView::Trace(run_id) => trace_lines(app, area, run_id),
        ShellView::Help => viewport_lines(help_lines(app, area), area.height, app.help_scroll),
        ShellView::Quickstart => {
            viewport_lines(quickstart_lines(app, area), area.height, app.help_scroll)
        }
        ShellView::Config => config_lines(app, area),
        ShellView::Tools => viewport_lines(tools_lines(app, area), area.height, app.tools_scroll),
        ShellView::Options(view) => options_lines(app, area, view),
        ShellView::SastTasks => sast_tasks_lines(app, area),
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
    }
}

fn viewport_lines(
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

fn viewport_start_for_cursor(total_rows: usize, visible_rows: usize, cursor: usize) -> usize {
    if total_rows <= visible_rows || visible_rows == 0 {
        return 0;
    }
    let max_start = total_rows.saturating_sub(visible_rows);
    let margin = visible_rows.saturating_sub(1) / 2;
    cursor.saturating_sub(margin).min(max_start)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

fn routing_mode(app: &ShellApp) -> RoutingMode {
    if app.scan.as_ref().is_some_and(|scan| scan.running)
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

fn routing_mode_segment(app: &ShellApp) -> String {
    match routing_mode(app) {
        RoutingMode::Shell => "mode:shell",
        RoutingMode::Module => "mode:module",
        RoutingMode::Agent => "mode:agent",
        RoutingMode::Plan => "mode:plan",
        RoutingMode::Run => "mode:run",
    }
    .to_string()
}

fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    // Drop the trailing "· kuzushi shell" segment — the user is in the
    // shell already (the prompt and the top-row mode label both say so),
    // and the muted suffix burned cells the catalog title needed for
    // breathing room. Modules count is the more useful sub-title.
    let module_count = app.registry.modules().count();
    lines.push(Line::from(vec![
        Span::styled("KUZUSHI · CATALOG", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{module_count} modules"), theme::muted()),
    ]));
    lines.push(blank());

    let modules = app.registry.modules().collect::<Vec<_>>();
    if modules.is_empty() {
        lines.push(styled("[!] No modules loaded", theme::warn()));
        lines.push(muted("Run kuzushi modules to inspect the native registry."));
        return lines;
    }

    if !app.catalog_expanded {
        if app.target.is_none() {
            lines.push(styled(
                "[!] no target selected; `scan .` uses the current directory",
                theme::warn(),
            ));
        } else if app.findings.is_empty() {
            lines.push(styled(
                "[!] active target has no persisted findings yet",
                theme::warn(),
            ));
        }
        lines.push(next_action_line(
            &catalog_next_hint(app),
            area.width as usize,
        ));
        if app.findings.is_empty() {
            lines.push(muted(&fit(&app.first_finding_hint(), area.width as usize)));
        }
        lines.push(muted(&fit(
            "Quickstart: quickstart · Context: context build · Runtime: model",
            area.width as usize,
        )));
        lines.push(muted(
            "Type help, modules, use <module>, scan, or run <tool> [json].",
        ));
        return lines;
    }

    if let Some(module) = modules
        .iter()
        .find(|module| module.metadata().id == "sast")
        .or_else(|| {
            modules
                .iter()
                .find(|module| module.metadata().id == "semgrep")
        })
        .or_else(|| modules.first())
    {
        // Reserve space for the leading `▸ NEXT ` glyph + the literal
        // `Run <id> against the active target — ` prefix so the truncation
        // budget tracks the user's actual terminal width instead of an
        // 88-column historical default.
        let prefix = format!("Run {} against the active target — ", module.metadata().id);
        let budget = (area.width as usize)
            .saturating_sub(prefix.chars().count() + 8)
            .max(40);
        let hint = format!(
            "{prefix}{}",
            short_sentence(&module.metadata().description, budget)
        );
        lines.push(next_action_line(&hint, area.width as usize));
        lines.push(blank());
    }

    let mut grouped: BTreeMap<&'static str, Vec<_>> = BTreeMap::new();
    for module in modules {
        grouped
            .entry(catalog_module_category(
                &module.metadata().id,
                module.metadata().kind,
            ))
            .or_default()
            .push(module);
    }

    for category in ["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"] {
        let Some(rows) = grouped.get(category) else {
            continue;
        };
        let (_, blurb) = module_category_blurb(category);
        let widths = module_table_widths(area.width);
        lines.push(category_divider(category, blurb, area.width));
        for module in rows {
            lines.push(catalog_module_row(
                &module.metadata().id,
                &module.metadata().description,
                app.focused_module.as_deref() == Some(module.metadata().id.as_str()),
                &widths,
            ));
        }
        lines.push(blank());
    }

    lines
}

fn module_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(module_id) = &app.focused_module else {
        return catalog_lines(app, area);
    };
    let Some(module) = app
        .registry
        .modules()
        .find(|module| module.metadata().id == *module_id)
    else {
        return catalog_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(transcript_line(
        ">",
        &format!("/use {}", module.metadata().id),
        false,
    ));
    let primary_tool = module
        .tools()
        .first()
        .map(|tool| tool.name.as_str())
        .unwrap_or("no-tool");
    lines.push(transcript_line(
        "use",
        &format!(
            "focused module {} · primary tool {}",
            module.metadata().id,
            primary_tool
        ),
        false,
    ));
    lines.push(Line::from(vec![
        Span::styled(module.metadata().id.clone(), theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.metadata().name.clone(), theme::muted()),
    ]));
    lines.push(indent(
        muted(&short_sentence(
            &module.metadata().description,
            area.width.saturating_sub(2) as usize,
        )),
        2,
    ));
    lines.push(blank());

    if module.tools().is_empty() {
        lines.push(muted("No shell tools are exposed by this module."));
    } else {
        lines.push(divider("TOOLS", area.width));
        for tool in module.tools() {
            lines.push(tool_console_row(
                &tool.name,
                &tool.description,
                tool.headless,
                area.width,
            ));
        }
    }

    lines.push(blank());
    let activity_label = match module.metadata().id.as_str() {
        "recon" => Some("RECENT RECON ACTIVITY"),
        "carlini-threat-hunt" => Some("RECENT THREAT-HUNT ACTIVITY"),
        "agentic-sast" => Some("RECENT AGENTIC-SAST ACTIVITY"),
        _ => None,
    };
    if let Some(label) = activity_label {
        let activity = recent_module_activity_lines(app, module.metadata().id.as_str(), 8);
        if !activity.is_empty() {
            lines.push(section_header_line(label, area.width));
            lines.extend(activity);
            lines.push(blank());
        }
    }
    lines.extend(module_playbook_lines(
        module.metadata().id.as_str(),
        area.width,
    ));

    lines
}

/// Pull the most recent N log lines that look like they came from the given
/// module (by prefix or body match). Returns oldest-first.
fn recent_module_log(app: &ShellApp, module_id: &str, take: usize) -> Vec<(String, String)> {
    let module_id = module_id.to_string();
    let mut matches: Vec<(String, String)> = app
        .log
        .iter()
        .rev()
        .filter(|line| {
            line.prefix == module_id
                || line.prefix.starts_with(&format!("{module_id}:"))
                || line.body.contains(&format!("{module_id}:"))
                || (module_id == "recon"
                    && (line.prefix == "tool" || line.prefix == "result")
                    && line.body.contains("recon"))
        })
        .take(take)
        .map(|line| (line.prefix.clone(), line.body.clone()))
        .collect();
    matches.reverse();
    matches
}

/// Render the "RECENT … ACTIVITY" rows for a given module, preferring
/// structured cached snapshots over freeform `app.log` grep where possible.
///
/// The grep path (`recent_module_log`) is brittle — it depends on log line
/// shape and disappears when the bounded `app.log` ring is truncated.
/// Whenever a tool dispatcher has populated a `*_snapshot` field on the
/// app (`recon_snapshot`, `carlini_snapshot`, `agentic_sast_snapshot`),
/// we render directly from typed data here. The grep is the fallback when
/// no snapshot has been cached yet.
fn recent_module_activity_lines(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<Line<'static>> {
    match module_id {
        "recon" => {
            if let Some(snapshot) = app.recon_snapshot.as_ref() {
                let lines = recon_snapshot_lines(snapshot, take);
                if !lines.is_empty() {
                    return lines;
                }
            }
        }
        "carlini-threat-hunt" => {
            if let Some(report) = app.carlini_snapshot.as_ref() {
                return carlini_snapshot_lines(report);
            }
        }
        "agentic-sast" => {
            if let Some(report) = app.agentic_sast_snapshot.as_ref() {
                return agentic_sast_snapshot_lines(report);
            }
        }
        _ => {}
    }

    // Fallback: existing log-grep path (brittle but unchanged from before
    // the snapshot caching was introduced).
    let recent = recent_module_log(app, module_id, take);
    let mut out = Vec::new();
    for (prefix, body) in &recent {
        for body_line in body.lines() {
            out.push(transcript_line(prefix, body_line, false));
        }
    }
    out
}

/// Format a recon snapshot as one transcript line per host/service hit,
/// matching the design mockup `design/mockups/recon.jsx::hit()`:
///   `▸ host:port  service  banner`
/// Up to `take` rows total. If services are empty, falls back to one row
/// per host (so single-host fingerprint scans still surface the host).
fn recon_snapshot_lines(snapshot: &super::app::ReconSnapshot, take: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let host_label = |service: &kuzushi_core::ReconService| -> String {
        snapshot
            .hosts
            .iter()
            .find(|host| host.id == service.host_id)
            .map(|host| {
                host.hostname
                    .clone()
                    .unwrap_or_else(|| host.address.clone())
            })
            .unwrap_or_else(|| "unknown".to_string())
    };

    if !snapshot.services.is_empty() {
        for service in snapshot.services.iter().take(take) {
            let host = host_label(service);
            let svc = service
                .name
                .clone()
                .unwrap_or_else(|| service.proto.clone());
            let banner = service
                .banner
                .clone()
                .unwrap_or_else(|| service.state.clone());
            lines.push(Line::from(vec![
                Span::styled(" ▸ ", theme::warn()),
                Span::styled(host, theme::primary()),
                Span::styled(":", theme::subtle()),
                Span::styled(format!("{}", service.port), theme::accent()),
                Span::raw("  "),
                Span::styled(pad(&svc, 14), theme::muted()),
                Span::styled(banner, theme::primary()),
            ]));
        }
    } else {
        for host in snapshot.hosts.iter().take(take) {
            let label = host
                .hostname
                .clone()
                .unwrap_or_else(|| host.address.clone());
            lines.push(Line::from(vec![
                Span::styled(" ▸ ", theme::warn()),
                Span::styled(label, theme::primary()),
                Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
                Span::styled(host.state.clone(), theme::muted()),
            ]));
        }
    }
    lines
}

/// Format a carlini-threat-hunt snapshot as a small transcript block:
/// actor / finding counts plus cost. Top finding lines are added when
/// they fit, mirroring the textual `output()` summary on the report.
fn carlini_snapshot_lines(report: &kuzushi_core::CarliniThreatHuntReport) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(transcript_line(
        "result",
        &format!(
            "carlini-threat-hunt: {} finding{} from {} actor{} ({} run{})",
            report.count,
            if report.count == 1 { "" } else { "s" },
            report.actors,
            if report.actors == 1 { "" } else { "s" },
            report.actor_runs,
            if report.actor_runs == 1 { "" } else { "s" },
        ),
        false,
    ));
    lines.push(transcript_line(
        "cost",
        &format!("cost ${:.4}", report.cost_usd),
        false,
    ));
    for finding in report.findings.iter().take(5) {
        lines.push(transcript_line(
            "finding",
            &format!(
                "{} {} {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line,
            ),
            false,
        ));
    }
    lines
}

/// Format an agentic-sast snapshot as a one-line summary plus up to
/// five top finding rows. Mirrors the `AgenticSastReport::output` shape
/// but as styled transcript lines.
fn agentic_sast_snapshot_lines(report: &kuzushi_core::AgenticSastReport) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(transcript_line(
        "result",
        &format!(
            "agentic-sast: {} finding{} under {}",
            report.count,
            if report.count == 1 { "" } else { "s" },
            report.target,
        ),
        false,
    ));
    lines.push(transcript_line(
        "cost",
        &format!("cost ${:.4}", report.cost_usd),
        false,
    ));
    for finding in report.findings.iter().take(5) {
        lines.push(transcript_line(
            "finding",
            &format!(
                "{} {} {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line,
            ),
            false,
        ));
    }
    lines
}

fn module_run_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let scan = app.scan.as_ref();
    let target = scan
        .map(|scan| compact_target_path(&scan.target.display().to_string()))
        .or_else(|| {
            app.target
                .as_ref()
                .map(|path| compact_target_path(&path.display().to_string()))
        })
        .unwrap_or_else(|| "target:none".to_string());
    let stage = scan.map(scan_status).unwrap_or_else(|| "idle".to_string());
    let findings = scan
        .map(|scan| scan.findings_count)
        .unwrap_or(app.findings.len());
    let run = scan
        .and_then(|scan| scan.run_id.as_ref())
        .map(|run_id| format!("run {}", short(run_id)))
        .unwrap_or_else(|| {
            if scan.is_some() {
                "run pending".to_string()
            } else {
                "tool run".to_string()
            }
        });

    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(
            run_state_glyph(scan, app.spinner_phase as usize),
            run_state_style(scan),
        ),
        Span::raw(" "),
        Span::styled(target, theme::label()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::raw(stage),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{findings} finding(s)"), theme::muted()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(run, theme::muted()),
    ]));
    lines.push(blank());

    let active_stage = scan.map(|scan| scan.stage.as_str()).unwrap_or("idle");
    let scan_running = scan.is_some_and(|s| s.running);
    let scan_done =
        scan.is_some() && !scan_running && scan.and_then(|s| s.error.as_ref()).is_none();
    lines.push(divider("SCAN PROGRESS", area.width));

    let sast_rows = app.sast_task_rows();
    let show_per_task = sast_rows.iter().any(|r| r.selected)
        && app.focused_module.as_deref() == Some("sast")
        && (scan_running || scan_done);
    let use_real_progress = show_per_task && app.scan_progress.is_some();
    if use_real_progress {
        // Snapshot-preferred branch: render real `done/total` from
        // `ScanProgress.per_task` (stable BTreeMap order) instead of the
        // binary running/done placeholder bars below.
        let progress = app.scan_progress.as_ref().expect("checked above");
        for (task_id, (done, total)) in progress.per_task.iter() {
            let kind = if *total == 0 {
                ProgressKind::Failing
            } else if done >= total {
                ProgressKind::Done
            } else {
                ProgressKind::Active
            };
            let status = if *total == 0 {
                "queued".to_string()
            } else if done >= total {
                "done".to_string()
            } else {
                "running…".to_string()
            };
            lines.push(progress_bar_line(task_id, *done, *total, &status, kind));
        }
        lines.push(progress_bar_line(
            "triage",
            0,
            findings.max(1),
            if findings > 0 {
                "queued after scan"
            } else {
                "waiting for findings"
            },
            if findings > 0 {
                ProgressKind::Active
            } else {
                ProgressKind::Failing
            },
        ));
    } else if show_per_task {
        for row in &sast_rows {
            if !row.selected {
                continue;
            }
            let (kind, done_count, total, status) = if scan_done {
                (ProgressKind::Done, 1usize, 1usize, "done".to_string())
            } else {
                (ProgressKind::Active, 0usize, 1usize, "running…".to_string())
            };
            lines.push(progress_bar_line(row.id, done_count, total, &status, kind));
        }
        lines.push(progress_bar_line(
            "triage",
            if scan_done && findings > 0 { 0 } else { 0 },
            findings.max(1),
            if findings > 0 {
                "queued after scan"
            } else {
                "waiting for findings"
            },
            if findings > 0 {
                ProgressKind::Active
            } else {
                ProgressKind::Failing
            },
        ));
    } else if app.focused_module.as_deref() == Some("sast") || scan.is_some() {
        // SAST pipeline placeholder — context:build → sast:scan → triage:run.
        // Only render this when the focused module is `sast` or there's an
        // actual scan running; otherwise the fixed three-row pipeline is
        // misleading for non-SAST modules (chrome-rce, threat-model, etc.).
        lines.push(pipeline_row(
            if active_stage.contains("context") {
                "⏵"
            } else {
                "✓"
            },
            "context:build",
            if active_stage.contains("context") {
                "active"
            } else {
                "ready"
            },
        ));
        lines.push(pipeline_row(
            if scan_running {
                "⏵"
            } else if scan.is_some() {
                "✓"
            } else {
                "○"
            },
            "sast:scan",
            active_stage,
        ));
        lines.push(pipeline_row(
            "○",
            "triage:run",
            if findings > 0 {
                "queued after scan"
            } else {
                "waiting for findings"
            },
        ));
    } else {
        let module = app.focused_module.as_deref().unwrap_or("tool");
        lines.push(pipeline_row(
            "○",
            module,
            "no scan in flight; `run .` dispatches the module's primary tool",
        ));
    }

    if let Some(error) = scan.and_then(|scan| scan.error.as_ref()) {
        lines.push(blank());
        // Word-wrap so the actionable next-step suggestion (e.g.
        // `pipx install semgrep` or `brew install semgrep`) doesn't get
        // truncated at the cell width. Continuation rows reuse the
        // transcript "…" glyph so the prefix doesn't repeat.
        let body_width = (area.width as usize).saturating_sub(6).max(20);
        let wrapped = wrap_text(error, body_width);
        for (index, segment) in wrapped.iter().enumerate() {
            lines.push(transcript_line("error", segment, index > 0));
        }
    }

    if !app.findings.is_empty() {
        lines.push(blank());
        let triaged = app.findings.iter().filter(|f| f.triage.is_some()).count();
        let pending = app.findings.len().saturating_sub(triaged);
        let header = format!("FINDINGS · {triaged} triaged · {pending} pending",);
        lines.push(section_header_line(&header, area.width));
        let aliases = sorted_finding_aliases(&app.findings);
        for (alias, finding) in aliases.into_iter().take(8) {
            lines.push(compact_finding_row(
                &alias,
                finding.severity,
                &finding.title,
                &finding_location(&finding),
                area.width,
            ));
        }
        if app.findings.len() > 8 {
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(
                    format!("… {} more · ", app.findings.len() - 8),
                    theme::muted(),
                ),
                Span::styled("/findings", theme::accent()),
                Span::styled(" to drill in", theme::muted()),
            ]));
        }
    }

    lines.push(blank());
    lines.push(divider("TRANSCRIPT", area.width));
    let body_budget = area.height.saturating_sub(lines.len() as u16) as usize;
    let transcript = transcript_lines(app, body_budget.saturating_sub(1).max(0));
    lines.extend(transcript);
    if scan_running && body_budget > 0 {
        lines.push(streaming_cursor_line());
    }
    lines
}

/// One-row streaming cursor block — a single styled cell at the end of the
/// transcript that mirrors the design's `<span className="cursor">` from the
/// running mockups (sast-running.jsx, carlini-running.jsx, agentic-sast-running.jsx).
fn streaming_cursor_line() -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            " ",
            Style::default().fg(theme::TERM_BG).bg(theme::T_PRIMARY),
        ),
    ])
}

fn findings_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    // Filter chip row, mirroring `design/mockups/findings.jsx::chip`:
    //   filters [all:38]  critical:5  high:11  medium:14  low:8
    // Active chip wears `[label:n]` brackets in c-accent; inactive chips
    // drop the brackets and render in c-muted with the count after the
    // colon. Counts come from the persisted finding set so operators can
    // size the filter buckets at a glance.
    let counts = SeverityCounts::from_findings(&app.findings);
    let total = app.findings.len();
    let mut chip_spans: Vec<Span<'static>> = Vec::new();
    chip_spans.push(Span::styled("filters ", theme::label()));
    chip_spans.push(Span::styled(format!("[all:{total}]"), theme::accent()));
    for (label, n, style) in [
        ("critical", counts.critical, theme::severity(Severity::Critical)),
        ("high", counts.high, theme::severity(Severity::High)),
        ("medium", counts.medium, theme::severity(Severity::Medium)),
        ("low", counts.low, theme::severity(Severity::Low)),
    ] {
        chip_spans.push(Span::raw("  "));
        chip_spans.push(Span::styled(format!("{label}:{n}"), style));
    }
    lines.push(Line::from(chip_spans));
    lines.push(blank());

    if app.findings.is_empty() {
        lines.push(muted("No findings yet."));
        let hint = if app.context_view.exists {
            "Next: scan — runs configured scanners against the active target."
        } else {
            "Next: scan after `context build` so scanners have structure to walk."
        };
        lines.push(muted(hint));
        return lines;
    }

    let triaged = app.findings.iter().filter(|f| f.triage.is_some()).count();
    let pending = app.findings.len().saturating_sub(triaged);
    lines.push(section_header_line(
        &format!(
            "FINDINGS · {} · {triaged} triaged · {pending} pending",
            app.findings.len()
        ),
        area.width,
    ));

    let aliases = sorted_finding_aliases(&app.findings);
    let cursor = app.findings_cursor.min(aliases.len().saturating_sub(1));
    let mut body = Vec::new();
    for (index, (alias, finding)) in aliases.into_iter().enumerate() {
        let selected = app
            .selected_finding
            .as_ref()
            .is_some_and(|selected| selected.fingerprint.as_str() == finding.fingerprint.as_str());
        let cursor_row = app.findings_cursor == index;
        let marker = if cursor_row {
            "▌ "
        } else if selected {
            "* "
        } else {
            "  "
        };
        let marker_style = if cursor_row {
            theme::accent()
        } else if selected {
            theme::warn()
        } else {
            theme::subtle()
        };

        // Row 1: marker · alias · severity chip · title · location.
        // At narrow widths (<100 cols), location moves to row 2 so the title
        // doesn't get truncated to nothing.
        let alias_w = 8;
        let sev_w = 9;
        let prefix_used = 2 + alias_w + 2 + sev_w;
        let total = (area.width as usize).saturating_sub(prefix_used);
        let location = finding_location(&finding);
        let wide = area.width >= 100;
        let location_w = if wide {
            location.chars().count().min(total.saturating_sub(2)).max(8)
        } else {
            0
        };
        let name_w = if wide {
            total.saturating_sub(location_w + 2).max(12)
        } else {
            total.max(12)
        };
        let mut row1 = vec![
            Span::styled(marker, marker_style),
            Span::styled(pad(&alias, alias_w), theme::accent()),
            Span::raw("  "),
            Span::styled(
                pad(&finding.severity.as_str().to_uppercase(), sev_w),
                theme::severity(finding.severity),
            ),
            Span::styled(pad(&fit(&finding.title, name_w), name_w), theme::primary()),
        ];
        if wide {
            row1.push(Span::raw("  "));
            row1.push(Span::styled(fit(&location, location_w), theme::muted()));
        }
        body.push(Line::from(row1));

        // Row 2: indented muted detail (location at narrow widths +
        // verdict · conf · cwe · source · evidence).
        let verdict = finding_verdict_label(&finding);
        let conf = finding_confidence_label(&finding);
        let cwe = finding_cwe_label(&finding);
        let source = finding_source_label(&finding);
        let evidence = finding_evidence_preview(&finding);
        if wide {
            // Single indented detail line.
            let detail = format!("{verdict} · conf {conf} · {cwe} · {source} · {evidence}");
            body.push(indent(
                muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
                4,
            ));
        } else {
            // Narrow widths get a 3-row layout: location on its own line, then
            // verdict/conf/cwe/source. Keeps all identifiers visible at 80 cols.
            body.push(indent(
                muted(&fit(&location, area.width.saturating_sub(4) as usize)),
                4,
            ));
            let detail = format!("{verdict} · conf {conf} · {cwe} · {source}");
            body.push(indent(
                muted(&fit(&detail, area.width.saturating_sub(4) as usize)),
                4,
            ));
        }
    }

    let body_height = area.height.saturating_sub(lines.len() as u16) as usize;
    if body_height == 0 {
        return lines;
    }
    let row_height = if area.width >= 100 { 2 } else { 3 };
    let visible_rows = (body_height / row_height).max(1);
    let start_row = viewport_start_for_cursor(app.findings.len(), visible_rows, cursor);
    lines.extend(
        body.into_iter()
            .skip(start_row * row_height)
            .take(body_height),
    );
    lines
}

fn finding_detail_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(finding) = &app.selected_finding else {
        return findings_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(finding.severity.as_str(), theme::severity(finding.severity)),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(finding.title.clone(), theme::heading()),
    ]));
    lines.push(blank());
    if let Some(alias) = stable_finding_alias(&app.findings, &finding.fingerprint) {
        lines.push(detail("alias", &alias));
    }
    lines.push(detail(
        "location",
        &format!("{}:{}", finding.file_path, finding.start_line),
    ));
    lines.push(detail("rule", &finding.rule_id));
    lines.push(detail("tool", &finding.tool));
    lines.push(detail("fingerprint", &finding.fingerprint));
    lines.push(blank());
    lines.push(divider("EVIDENCE", area.width));
    for line in finding.message.lines().take(8) {
        lines.push(indent(
            Line::raw(fit(line, area.width.saturating_sub(2) as usize)),
            2,
        ));
    }

    if let Some(triage) = &finding.triage {
        lines.push(blank());
        lines.push(divider("TRIAGE", area.width));
        lines.push(detail("verdict", triage.verdict.as_str()));
        lines.push(detail("confidence", &format!("{:.2}", triage.confidence)));
        lines.push(detail("rationale", &triage.rationale));
    }

    lines
}

fn tune_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module = app.focused_module.as_deref().unwrap_or("semgrep");
    lines.push(blank());
    lines.push(divider("TUNE", area.width));
    lines.push(detail("module", module));
    lines.push(detail("severity floor", "medium"));
    lines.push(detail("triage confidence", "0.70"));
    lines.push(detail("scan concurrency", "adaptive"));
    lines.push(detail(
        "house rules",
        &format!(".kuzushi/house-rules/{module}.md"),
    ));
    lines.push(blank());
    lines.push(divider("ACTIONS", area.width));
    let cursor = app.tune_cursor_clamped();
    for (index, action) in crate::app::TuneAction::ORDER.iter().enumerate() {
        let selected = index == cursor;
        let marker = if selected { ">" } else { " " };
        let style = if selected {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            theme::primary()
        };
        lines.push(Line::styled(
            fit(&format!("{marker} {}", action.label()), area.width as usize),
            style,
        ));
        lines.push(Line::styled(
            fit(&format!("    {}", action.hint()), area.width as usize),
            theme::muted(),
        ));
    }
    lines.push(blank());
    match app.read_house_rules() {
        Some(text) if !text.trim().is_empty() => {
            lines.push(divider("HOUSE RULES", area.width));
            for raw in text
                .lines()
                .take((area.height as usize).saturating_sub(10).max(4))
            {
                lines.push(Line::raw(fit(raw, area.width as usize)));
            }
            lines.push(blank());
        }
        _ => {
            lines.push(muted(
                "(no house rules set; pick edit house rules and type a value)",
            ));
        }
    }
    lines.push(muted(
        "Up/Down move | Enter activate | show/set/reset direct | back",
    ));
    lines
}

fn threat_lines(app: &ShellApp, area: Rect, view: ThreatView) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(threat_nav(view));
    lines.push(blank());

    match view {
        ThreatView::Dfd => {
            lines.push(section_header_line("DFD · acme-checkout", area.width));
            lines.extend(dfd_canonical_lines());
            if let Some(doc) = current_threat_model_doc(app) {
                if let Some(nodes) = dfd_nodes_from_doc(&doc) {
                    lines.push(blank());
                    lines.push(section_header_line(
                        &format!("NODES FROM threat-model.json · {}", nodes.len()),
                        area.width,
                    ));
                    for (id, node_type, zone) in nodes.into_iter().take(8) {
                        lines.push(Line::from(vec![
                            Span::raw("   "),
                            Span::styled(pad(&id, 24), theme::accent()),
                            Span::styled(pad(&node_type, 16), theme::muted()),
                            Span::styled(zone, theme::subtle()),
                        ]));
                    }
                }
            }
        }
        ThreatView::Stride => {
            let doc = current_threat_model_doc(app);
            let rollup = doc
                .as_ref()
                .and_then(stride_rollup_from_doc)
                .unwrap_or_else(stride_rollup_rows);
            let total_issues: usize = rollup.iter().map(|r| r.3).sum();
            lines.push(section_header_line(
                &format!("STRIDE ROLLUP · {total_issues} issues"),
                area.width,
            ));
            for (letter, sev, category, count, description) in &rollup {
                lines.push(stride_row(
                    letter,
                    *sev,
                    category,
                    *count,
                    description,
                    area.width,
                ));
            }
        }
        ThreatView::Stories => {
            let doc = current_threat_model_doc(app);
            let stories = doc
                .as_ref()
                .and_then(stories_from_doc)
                .unwrap_or_else(canonical_stories_fixture);
            lines.push(section_header_line(
                &format!("ATTACKER STORIES · {}", stories.len()),
                area.width,
            ));
            for (id, severity, title, attack, location) in stories.into_iter().take(8) {
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled("▸ ", theme::warn()),
                    Span::styled(pad(&id, 8), theme::accent()),
                    Span::styled(
                        pad(&severity.as_str().to_uppercase(), 9),
                        theme::severity(severity),
                    ),
                    Span::styled(title, theme::primary()),
                ]));
                if !attack.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("              "),
                        Span::styled("attack ", theme::subtle()),
                        Span::styled(attack, theme::muted()),
                    ]));
                }
                if !location.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("              "),
                        Span::styled("loc    ", theme::subtle()),
                        Span::styled(location, theme::muted()),
                    ]));
                }
            }
        }
        ThreatView::Scope => {
            let doc = current_threat_model_doc(app);
            let buckets = doc
                .as_ref()
                .and_then(scope_buckets_from_doc)
                .unwrap_or_else(canonical_scope_buckets);
            let total: usize = buckets.iter().map(|(_, _, items)| items.len()).sum();
            lines.push(section_header_line(
                &format!("SCOPE · {total} issues"),
                area.width,
            ));
            for (severity, label, items) in &buckets {
                if items.is_empty() {
                    continue;
                }
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        format!("{} · {}", label.to_uppercase(), items.len()),
                        theme::severity(*severity),
                    ),
                ]));
                for item in items.iter().take(4) {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled("• ", theme::subtle()),
                        Span::styled(item.clone(), theme::muted()),
                    ]));
                }
                if items.len() > 4 {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled(format!("… {} more", items.len() - 4), theme::subtle()),
                    ]));
                }
            }
            lines.push(blank());
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled("OUT OF SCOPE", theme::muted()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("      "),
                Span::styled("• ", theme::subtle()),
                Span::styled("generated caches, vendored fixtures", theme::muted()),
            ]));
        }
        ThreatView::Summary => {
            let doc = current_threat_model_doc(app);
            let rollup = doc
                .as_ref()
                .and_then(stride_rollup_from_doc)
                .unwrap_or_else(stride_rollup_rows);
            let total_issues: usize = rollup.iter().map(|r| r.3).sum();
            lines.push(section_header_line(
                &format!("THREAT MODEL · {total_issues} issues"),
                area.width,
            ));
            for (letter, sev, category, count, description) in &rollup {
                lines.push(stride_row(
                    letter,
                    *sev,
                    category,
                    *count,
                    description,
                    area.width,
                ));
            }
            lines.push(blank());
            lines.push(transcript_line(
                "agent",
                "biggest delta from last model: admin.acme-checkout.com shares the jwt secret.",
                false,
            ));
            lines.push(transcript_line(
                "flow",
                "recommend split signing keys + audience claim",
                false,
            ));
            lines.push(transcript_line(
                "log",
                "artifact .kuzushi/threat-model.json (proposed v4 · +12 −3)",
                false,
            ));
        }
    }

    lines
}

fn threat_editor_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("THREAT MODEL EDIT", area.width));
    lines.push(detail("artifact", ".kuzushi/threat-model.json"));
    lines.push(detail("mode", "operator edits"));
    lines.push(detail("sections", "elements, boundaries, stories, scope"));
    lines
}

fn prompts_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module = app.focused_module.as_deref().unwrap_or("semgrep");
    lines.push(blank());
    lines.push(divider("PROMPTS", area.width));
    lines.push(detail("module", module));
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            table_text(&["verb", "source", "override path"], &[12, 10, 28]),
            theme::subtle(),
        ),
    ]));
    let cursor = app.prompts_cursor_clamped();
    for (index, verb) in crate::app::ShellApp::PROMPT_VERB_NAMES.iter().enumerate() {
        let selected = index == cursor;
        let marker = if selected { ">" } else { " " };
        let style = if selected {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            theme::primary()
        };
        let path = format!(".kuzushi/prompts/{module}/{verb}.md");
        lines.push(Line::styled(
            fit(
                &format!(
                    "{marker} {}",
                    table_text(
                        &[verb, "builtin", &path],
                        &[12, 10, value_width(area, 28)],
                    )
                ),
                area.width as usize,
            ),
            style,
        ));
    }
    lines.push(blank());
    lines.push(muted(
        "Up/Down row | e edit | s show | d diff | r reset | S set | Enter show | back",
    ));
    lines
}

fn actor_detail_lines(app: &ShellApp, area: Rect, index: usize) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(&format!("ACTOR {index}"), area.width));
    lines.push(detail("tool", "semgrep:scan"));
    lines.push(detail(
        "status",
        app.scan
            .as_ref()
            .map(scan_status)
            .unwrap_or_else(|| "idle".to_string())
            .as_str(),
    ));
    lines.push(detail("filter", app.actor_detail_filter.label()));
    lines.push(muted("f cycle filter | 0 reset | j/k/g/G scroll | back"));
    lines.push(blank());

    let visible = area.height.saturating_sub(8).max(2) as usize;
    let filter = app.actor_detail_filter;
    let mut kept: Vec<&crate::app::LogLine> = app
        .log
        .iter()
        .filter(|line| filter.keeps(&line.prefix))
        .collect();
    let start = kept.len().saturating_sub(visible);
    kept.drain(..start);
    if kept.is_empty() {
        lines.push(muted("(no matching transcript entries under this filter)"));
    } else {
        for line in kept {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>8} ", line.prefix), theme::subtle()),
                Span::raw(line.body.clone()),
            ]));
        }
    }
    lines
}

fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUNS", area.width));
    if let Some(scan) = &app.scan {
        let widths = [10usize, 18, 10, value_width(area, 40)];
        lines.push(aligned_header(
            &["run", "status", "findings", "target"],
            &widths,
        ));
        lines.push(aligned_row(
            &[
                scan.run_id
                    .as_deref()
                    .map(short)
                    .unwrap_or_else(|| "pending".to_string()),
                scan_status(scan),
                scan.findings_count.to_string(),
                scan.target.display().to_string(),
            ],
            &widths,
        ));
    } else {
        lines.push(muted(
            "No scan run is active in this shell session. Next: `scan` to start one, or `replay <runId>` for a past run on disk.",
        ));
    }
    lines
}

fn replay_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPLAY", area.width));
    lines.push(detail("run", run_id));
    let summary_path = run_artifact_path(app, run_id, "summary.json");
    let triage_path = run_artifact_path(app, run_id, "triage.jsonl");
    lines.push(run_artifact_detail("summary", &summary_path));
    lines.push(run_artifact_detail("triage", &triage_path));
    if !summary_path.exists() {
        lines.push(blank());
        lines.push(muted(
            "(run artefacts not on disk; check `show runs` for valid runIds)",
        ));
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

fn trace_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TRACE", area.width));
    lines.push(detail("run", run_id));
    let triage_path = run_artifact_path(app, run_id, "triage.jsonl");
    let verify_path = run_artifact_path(app, run_id, "verify.jsonl");
    lines.push(run_artifact_detail("triage", &triage_path));
    lines.push(run_artifact_detail("verify", &verify_path));
    if !triage_path.exists() && !verify_path.exists() {
        lines.push(blank());
        lines.push(muted(
            "(run artefacts not on disk; check `show runs` for valid runIds)",
        ));
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

fn run_artifact_path(app: &ShellApp, run_id: &str, leaf: &str) -> std::path::PathBuf {
    let runs_root = app
        .target
        .as_deref()
        .map(|target| target.join(".kuzushi/runs"))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/runs"));
    runs_root.join(run_id).join(leaf)
}

fn run_artifact_detail(label: &str, path: &std::path::Path) -> Line<'static> {
    let display = path.display().to_string();
    let suffix = if path.exists() { "" } else { " (missing)" };
    detail(label, &format!("{display}{suffix}"))
}

fn alias_reference_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let aliases = sorted_finding_aliases(&app.findings);
    lines.push(blank());
    if aliases.is_empty() {
        lines.push(muted("aliases: load findings first with findings"));
        return lines;
    }
    lines.push(divider("ALIASES", area.width));
    for (alias, finding) in aliases.into_iter().take(3) {
        lines.push(detail(
            &alias,
            &format!("{} {}", short(&finding.fingerprint), finding.title),
        ));
    }
    lines
}

fn help_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HELP", area.width));
    lines.push(muted(&fit(
        "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode.",
        area.width as usize,
    )));
    let examples = shell_help_examples();
    if !examples.is_empty() {
        lines.push(muted(&fit(
            &format!("Examples: {}", examples.join(" | ")),
            area.width as usize,
        )));
    }
    let widths = help_table_widths(area.width);
    for category in ShellCommandCategory::ORDER {
        lines.push(blank());
        lines.push(category_divider(
            category.label(),
            help_category_blurb(category),
            area.width,
        ));
        for spec in shell_command_specs()
            .iter()
            .filter(|spec| spec.category == category)
        {
            let command = fit(spec.command, widths.first().copied().unwrap_or(18));
            let aliases = help_alias_text(spec, widths.get(1).copied().unwrap_or(18));
            if widths.len() == 2 {
                lines.push(table_row(&[&command, &aliases], &widths));
            } else {
                let description = fit(spec.description, widths.get(2).copied().unwrap_or(20));
                lines.push(table_row(&[&command, &aliases, &description], &widths));
            }
        }
    }
    lines
}

/// Section blurbs for the `/help` view, aligned with `design/mockups/help.jsx::sec`.
pub(super) fn help_category_blurb(category: ShellCommandCategory) -> &'static str {
    match category {
        ShellCommandCategory::Navigation => "browse modules and tools",
        ShellCommandCategory::RunScan => "dispatch tools and scans",
        ShellCommandCategory::OptionsTasks => "options + sast task control",
        ShellCommandCategory::ContextKb => "workspace + attachments",
        ShellCommandCategory::FindingsEvidence => "browse / open / triage findings",
        ShellCommandCategory::AuthConfigModel => "auth, model, runtime config",
        ShellCommandCategory::Session => "history, cost, lifecycle",
    }
}

fn quickstart_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("QUICKSTART", area.width));
    lines.push(blank());
    lines.push(Line::styled(
        "Welcome to kuzushi. Five steps to your first finding:",
        theme::heading(),
    ));
    lines.push(blank());
    let scan_step = if app.target.is_some() {
        "scan                       run configured scanners on the active target"
    } else {
        "scan .                     run configured scanners on this directory"
    };
    let steps = [
        ("1", scan_step),
        ("2", "findings                   browse persisted findings"),
        ("3", "context build              write .kuzushi/context-snapshot.json"),
        (
            "4",
            "model                      choose an explicit provider/model for ask/triage",
        ),
        (
            "5",
            "ask <question>             ask after a model is configured",
        ),
    ];
    for (num, step) in steps {
        lines.push(Line::from(vec![
            Span::styled(format!("  {num}. "), theme::accent()),
            Span::styled(step.to_string(), theme::primary()),
        ]));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "Tip: Ctrl+O toggles the live event timeline.",
        area.width as usize,
    )));
    lines.push(muted(&fit(
        &format!(
            "First-finding path: `{}` then `findings`.",
            app.first_finding_scan_command()
        ),
        area.width as usize,
    )));
    lines.push(blank());
    lines.push(muted(&fit(
        "Type `help` for the full command reference, or `back` to return.",
        area.width as usize,
    )));
    lines
}

fn help_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    if total < 72 {
        let command = total.min(if total < 48 { 14 } else { 18 });
        let aliases = total.saturating_sub(command + 2);
        return vec![command, aliases];
    }

    let command = if total < 96 { 22 } else { 28 };
    let aliases = if total < 96 { 24 } else { 32 };
    let description = total.saturating_sub(command + aliases + 4);
    vec![command, aliases, description]
}

fn help_alias_text(spec: &ShellCommandSpec, max_chars: usize) -> String {
    let mut aliases = Vec::new();
    for alias in spec.aliases {
        if *alias == spec.command || aliases.contains(alias) {
            continue;
        }
        aliases.push(*alias);
    }
    if aliases.is_empty() {
        "-".to_string()
    } else {
        fit(&aliases.join(", "), max_chars)
    }
}

fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("CONFIG", area.width));
    lines.push(detail(
        "backend",
        crate::app::runtime_backend_label(&app.config),
    ));
    lines.push(detail("provider", &app.provider_label()));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(detail(
        "reasoning",
        app.session_thinking_level.as_deref().unwrap_or("default"),
    ));
    let auth_status = if std::env::var_os(&app.config.runtime.api_key_env).is_some() {
        "set; value hidden"
    } else {
        "missing"
    };
    lines.push(detail(
        "auth envs",
        &format!(
            "{} ({auth_status}); ANTHROPIC_API_KEY ({})",
            app.config.runtime.api_key_env,
            if std::env::var_os("ANTHROPIC_API_KEY").is_some() {
                "set; value hidden"
            } else {
                "missing"
            }
        ),
    ));
    lines.push(detail(
        "oauth",
        &format!(
            "openai-codex {}; anthropic {}",
            crate::app::oauth_provider_status("openai-codex"),
            crate::app::oauth_provider_status("anthropic")
        ),
    ));
    lines.push(detail(
        "base url",
        app.config
            .runtime
            .base_url
            .as_deref()
            .unwrap_or("provider default"),
    ));
    lines.push(detail(
        "bridge",
        crate::app::bridge_command_status(&app.config),
    ));
    lines.push(detail(
        "cost",
        &if let Some(last) = app.last_tool_cost_usd {
            format!(
                "session ${:.4}; last tool ${:.4}",
                app.session_cost_usd, last
            )
        } else {
            "unavailable until a tool reports costUsd".to_string()
        },
    ));
    if app.config.model.is_none() {
        lines.push(detail(
            "onboarding",
            "Up/Down selects a model; Enter activates it. OAuth availability is shown below.",
        ));
    }
    lines.push(blank());
    lines.push(divider("MODELS", area.width));
    let widths = [2usize, 2, 28, 6, value_width(area, 28)];
    lines.push(aligned_header(&["", "#", "model", "effort", "auth"], &widths));
    for (index, choice) in crate::app::model_choices().iter().enumerate() {
        let marker = if index == app.selected_model_index {
            ">"
        } else {
            " "
        };
        lines.push(aligned_row(
            &[
                marker.to_string(),
                choice.index.to_string(),
                choice.id.to_string(),
                choice.thinking_level.to_string(),
                model_auth_status(choice),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "Up/Down select · Enter choose · model <n> [xhigh] · auth login openai-codex|anthropic",
        area.width as usize,
    )));
    lines
}

fn model_auth_status(choice: &crate::app::ModelChoice) -> String {
    match choice.provider {
        "openai" => {
            if std::env::var_os("OPENAI_API_KEY").is_some() {
                "OPENAI_API_KEY set".to_string()
            } else {
                "OPENAI_API_KEY missing".to_string()
            }
        }
        "openai-codex" => {
            let status = crate::app::oauth_provider_status("openai-codex");
            if status.starts_with("stored") {
                "OAuth ready".to_string()
            } else {
                "OAuth missing".to_string()
            }
        }
        "anthropic" => {
            let env_ready = std::env::var_os("ANTHROPIC_API_KEY").is_some();
            let oauth_ready = crate::app::oauth_provider_status("anthropic").starts_with("stored");
            match (env_ready, oauth_ready) {
                (true, true) => "ANTHROPIC_API_KEY/OAuth ready".to_string(),
                (true, false) => "ANTHROPIC_API_KEY set".to_string(),
                (false, true) => "OAuth ready".to_string(),
                (false, false) => "ANTHROPIC auth missing".to_string(),
            }
        }
        _ => choice.auth.to_string(),
    }
}

fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TOOLS", area.width));
    let widths = [28usize, 8, value_width(area, 38)];
    lines.push(aligned_header(&["tool", "headless", "description"], &widths));
    for tool in app.registry.tools() {
        lines.push(aligned_row(
            &[
                tool.name.clone(),
                tool.headless.to_string(),
                tool.description.clone(),
            ],
            &widths,
        ));
    }
    lines
}

fn options_lines(app: &ShellApp, area: Rect, view: &crate::app::OptionsView) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("OPTIONS", area.width));
    lines.push(detail("tool", &view.tool_name));
    lines.push(detail("view", options_filter_label(view.filter)));

    let Some(tool) = app.registry.resolve_tool(&view.tool_name) else {
        lines.push(blank());
        lines.push(muted(
            "Unknown tool. Run tools to inspect the native registry.",
        ));
        return lines;
    };

    let stored = app.option_store.effective_stored_values(&tool.name);
    let specs = tool
        .options
        .iter()
        .filter(|spec| option_visible(spec, view.filter, stored.get(&spec.name).is_some()))
        .collect::<Vec<_>>();

    if specs.is_empty() {
        lines.push(blank());
        let message = match view.filter {
            crate::app::OptionsFilter::Standard => {
                "No standard options. Run show advanced for hidden controls."
            }
            crate::app::OptionsFilter::Advanced => "No advanced options for this tool.",
            crate::app::OptionsFilter::Missing => "No missing required options for this tool.",
        };
        lines.push(muted(message));
        return lines;
    }

    lines.push(blank());
    lines.push(table_header(
        &["option", "value", "default", "req", "type", "description"],
        &option_table_widths(area.width),
    ));
    for spec in specs {
        let current = stored.get(&spec.name);
        let required = if spec.required && current.is_none() && spec.default.is_none() {
            "missing"
        } else if spec.required {
            "yes"
        } else {
            "no"
        };
        let description = option_description(spec);
        let widths = option_table_widths(area.width);
        lines.push(table_row(
            &[
                &spec.name,
                &current
                    .map(format_json_value)
                    .unwrap_or_else(|| "-".to_string()),
                &spec
                    .default
                    .as_ref()
                    .map(format_json_value)
                    .unwrap_or_else(|| "-".to_string()),
                required,
                option_type_label(spec.option_type),
                &fit(&description, widths.get(5).copied().unwrap_or(16)),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "set <key> <value> writes a session option; setg writes a global option for this shell session.",
        area.width as usize,
    )));
    lines
}

fn sast_tasks_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let rows = app.sast_task_rows();
    let enabled = rows.iter().filter(|row| row.selected).count();
    let blocked = rows.iter().filter(|row| row.source == "blocked").count();
    let mode = app
        .option_store
        .effective_stored_values("sast:scan")
        .get("taskMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "manual")
        .map(|_| "manual allowlist")
        .unwrap_or("auto + denylist");

    lines.push(blank());
    lines.push(divider("SAST TASKS", area.width));
    lines.push(detail("mode", mode));
    lines.push(detail(
        "selected",
        &format!("{enabled}/{} enabled, {blocked} blocked", rows.len()),
    ));
    lines.push(blank());
    lines.push(muted(&fit(
        "legend: [x] enabled · [ ] disabled · [A] advanced (off by default; allow with /task allow <id>) · [B] blocked",
        area.width as usize,
    )));
    lines.push(blank());
    lines.push(table_header(
        &["state", "id", "cost", "scan", "notes"],
        &sast_task_table_widths(area.width),
    ));
    let widths = sast_task_table_widths(area.width);
    for row in rows {
        lines.push(table_row(
            &[
                row.state,
                row.id,
                row.cost,
                row.scan_task,
                &fit(row.notes, widths.get(4).copied().unwrap_or(20)),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "/task block <id> · /task allow <id> · /task toggle [id] · /task mode auto|manual|toggle · /task reset",
        area.width as usize,
    )));
    lines
}

fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let view = &app.context_view;

    lines.push(blank());
    lines.push(divider("CONTEXT", area.width));
    lines.push(detail(
        "snapshot",
        &view
            .snapshot_path
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/context-snapshot.json".to_string()),
    ));
    lines.push(detail(
        "state",
        if view.exists { "present" } else { "missing" },
    ));
    lines.push(detail("status", &fit(&view.status, value_width(area, 10))));

    if view.exists {
        lines.push(detail(
            "target",
            view.target.as_deref().unwrap_or("unknown"),
        ));
        lines.push(detail(
            "discovery",
            view.discovery.as_deref().unwrap_or("unknown"),
        ));
        lines.push(detail(
            "files",
            &format!(
                "indexed={} total={}",
                view.files_indexed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                view.total_files
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ),
        ));
        lines.push(detail(
            "languages",
            &fit(&join_or_dash(&view.languages), value_width(area, 10)),
        ));
        lines.push(detail(
            "frameworks",
            &fit(&join_or_dash(&view.frameworks), value_width(area, 10)),
        ));
        lines.push(detail(
            "generated",
            &fit(&join_or_dash(&view.generated_slices), value_width(area, 10)),
        ));
        lines.push(detail(
            "stale",
            &fit(&join_or_dash(&view.stale_slices), value_width(area, 10)),
        ));
    } else {
        lines.push(blank());
        lines.push(muted(
            "No context snapshot exists yet. Run context build to write .kuzushi/context-snapshot.json.",
        ));
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "context build · context status · context regen repo · context regen app-model",
        area.width as usize,
    )));
    lines
}

fn workspace_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let view = &app.workspace_view;

    lines.push(blank());
    lines.push(divider("WORKSPACE", area.width));
    lines.push(detail("status", &fit(&view.status, value_width(area, 10))));
    lines.push(detail(
        "target",
        &view
            .root
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string()),
    ));
    lines.push(detail(
        "state",
        &view
            .state_dir
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2".to_string()),
    ));
    lines.push(detail(
        "findings db",
        &view
            .findings_db
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2/findings.sqlite3".to_string()),
    ));
    lines.push(detail(
        "findings",
        &view
            .findings_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    ));
    lines.push(detail(
        "last export",
        &view
            .last_export
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string()),
    ));

    if view.root.is_none() {
        lines.push(blank());
        lines.push(muted(
            "No active workspace is selected. Run scan <target> or start kuzushi shell --target .",
        ));
    }

    // Severity rollup bar — see `design/mockups/workspace.jsx::rollupBar`.
    // Surfaces the persisted-findings distribution at a glance so an
    // operator landing on `/workspace` sees the shape of the work without
    // jumping into `/findings` first.
    let total = app.findings.len();
    if total > 0 {
        let counts = SeverityCounts::from_findings(&app.findings);
        lines.push(blank());
        lines.push(divider(
            &format!("FINDINGS ROLLUP · {total} persisted"),
            area.width,
        ));
        for (label, n, severity) in [
            ("CRITICAL", counts.critical, Severity::Critical),
            ("HIGH    ", counts.high, Severity::High),
            ("MEDIUM  ", counts.medium, Severity::Medium),
            ("LOW     ", counts.low, Severity::Low),
        ] {
            lines.push(severity_rollup_bar(label, n, total, severity));
        }
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "workspace status · workspace export findings <path>.json · findings export <path>.json",
        area.width as usize,
    )));
    lines
}

/// Render a single `█████░░░░░░ N/total` rollup bar matching
/// `design/mockups/workspace.jsx::rollupBar`. Bar is 28 cells wide, with
/// the filled portion in the severity tint and the unfilled portion in
/// `theme::subtle()`.
fn severity_rollup_bar(label: &str, n: usize, total: usize, severity: Severity) -> Line<'static> {
    let bar_w: usize = 28;
    let filled = if total == 0 {
        0
    } else {
        ((bar_w * n) as f64 / total as f64).round() as usize
    };
    let filled = filled.clamp(if n > 0 { 1 } else { 0 }, bar_w);
    let empty = bar_w - filled;
    Line::from(vec![
        Span::raw(" "),
        Span::styled(label.to_string(), theme::severity(severity)),
        Span::styled(" [".to_string(), theme::subtle()),
        Span::styled("█".repeat(filled), theme::severity(severity)),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ".to_string(), theme::subtle()),
        Span::styled(format!("{n:>3}"), theme::primary()),
        Span::styled("/".to_string(), theme::subtle()),
        Span::styled(total.to_string(), theme::muted()),
    ])
}

fn knowledge_base_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module_id = app.kb_view.module_id.as_str();
    let attachments = app
        .kb_view
        .attachments
        .iter()
        .filter(|record| record.module_id == module_id)
        .collect::<Vec<_>>();
    let store = app
        .kb_view
        .store_path
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string());

    lines.push(blank());
    lines.push(divider("KB ATTACHMENTS", area.width));
    lines.push(detail("module", module_id));
    lines.push(detail("store", &store));
    lines.push(detail(
        "supported",
        &SUPPORTED_ATTACHMENT_MODULES.join(", "),
    ));
    lines.push(blank());

    lines.push(divider("KNOWN ARTIFACTS", area.width));
    if app.kb_view.artifacts.is_empty() {
        lines.push(muted("No known Rust artifacts for this module."));
    } else {
        lines.push(table_header(
            &["state", "path", "description"],
            &kb_artifact_widths(area.width),
        ));
        let widths = kb_artifact_widths(area.width);
        for artifact in &app.kb_view.artifacts {
            lines.push(table_row(
                &[
                    if artifact.exists {
                        "present"
                    } else {
                        "missing"
                    },
                    &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
                    &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
                ],
                &widths,
            ));
        }
    }

    lines.push(blank());
    lines.push(divider("ATTACHED", area.width));
    if attachments.is_empty() {
        lines.push(muted(
            "No attachments yet. Use attach <repo-relative-path> or attach https://example/...",
        ));
    } else {
        lines.push(table_header(
            &["id", "kind", "source", "status"],
            &kb_attachment_widths(area.width),
        ));
        let widths = kb_attachment_widths(area.width);
        for record in attachments {
            let kind = match &record.kind {
                AttachmentKind::Path => "path",
                AttachmentKind::Url => "url",
            };
            lines.push(table_row(
                &[
                    &record.id,
                    kind,
                    &fit(&record.source, widths.get(2).copied().unwrap_or(22)),
                    &fit(&record.status, widths.get(3).copied().unwrap_or(18)),
                ],
                &widths,
            ));
        }
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "kb [module] · attach <path-or-url> · detach <id> · reparse <id>",
        area.width as usize,
    )));
    lines
}

fn agent_chat_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("AGENT", area.width));

    let Some(agent) = &app.agent_chat else {
        lines.push(muted("No active question. Use ask <question> or ?text."));
        return lines;
    };

    let status = if agent.abort_requested {
        "abort requested"
    } else if agent.running {
        "running"
    } else if agent.error.is_some() {
        "failed"
    } else {
        "answered"
    };
    lines.push(detail("mode", "agent chat"));
    lines.push(detail("status", status));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(blank());
    lines.push(styled("question", theme::label()));
    lines.push(indent(
        muted(&fit(&agent.question, area.width.saturating_sub(2) as usize)),
        2,
    ));
    lines.push(blank());

    if let Some(error) = &agent.error {
        lines.push(styled("error", theme::danger()));
        lines.push(indent(
            muted(&fit(error, area.width.saturating_sub(2) as usize)),
            2,
        ));
    } else if let Some(answer) = &agent.answer {
        lines.push(styled("answer", theme::label()));
        for line in wrap_text(answer, area.width.saturating_sub(2) as usize)
            .into_iter()
            .take(8)
        {
            lines.push(indent(muted(&line), 2));
        }
    } else if agent.abort_requested {
        lines.push(muted(
            "Abort requested; waiting for pi-agent-core to return. Process kill is not confirmed.",
        ));
    } else {
        lines.push(muted("Waiting for pi-agent-core response..."));
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "ask <question> · ?text · model provider:model-id · back",
        area.width as usize,
    )));
    lines
}

fn history_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("COMMAND HISTORY", area.width));

    let entries = app
        .command_history
        .iter()
        .rev()
        .take(50)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        lines.push(muted("No command history yet. Next: help"));
    } else {
        let start = app.command_history.len().saturating_sub(entries.len()) + 1;
        let width = (start + entries.len()).to_string().len();
        for (offset, command) in entries.into_iter().rev().enumerate() {
            lines.push(row(&[
                format!("{:>width$}", start + offset, width = width),
                fit(command, area.width.saturating_sub(8) as usize),
            ]));
        }
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "clear · run <tool> · show runs · back",
        area.width as usize,
    )));
    lines
}

fn story_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("SESSION STORY · live event timeline", area.width));
    if let Some(scan) = &app.scan {
        let label = if scan.running {
            if scan.abort_requested {
                "abort requested"
            } else if app.is_scan_paused() {
                "paused"
            } else {
                "running"
            }
        } else {
            "idle"
        };
        lines.push(row(&[
            pad("scan", 10),
            fit(
                &format!(
                    "{label} · stage={} · findings={}",
                    scan.stage, scan.findings_count
                ),
                area.width.saturating_sub(14) as usize,
            ),
        ]));
    }
    lines.push(blank());

    let max_events = (area.height as usize).saturating_sub(8).max(8);
    let events = app
        .log
        .iter()
        .filter(|line| line.prefix != ">")
        .rev()
        .take(max_events)
        .collect::<Vec<_>>();
    if events.is_empty() {
        lines.push(muted(
            "No session events yet. Next: run <tool>, ask <question>, or scan <target>",
        ));
    } else {
        for line in events.into_iter().rev() {
            let body_width = area.width.saturating_sub(14) as usize;
            lines.push(row(&[pad(&line.prefix, 10), fit(&line.body, body_width)]));
        }
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "Ctrl+O toggle · /history commands · /show runs · /replay <runId> · /trace <runId>",
        area.width as usize,
    )));
    lines
}

fn kb_artifact_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 7;
    let path = if total < 88 { 30 } else { 42 };
    let gaps = 4;
    let description = total.saturating_sub(state + path + gaps).max(16);
    vec![state, path, description]
}

fn kb_attachment_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = 14;
    let kind = 4;
    let source = if total < 88 { 24 } else { 36 };
    let gaps = 6;
    let status = total.saturating_sub(id + kind + source + gaps).max(16);
    vec![id, kind, source, status]
}

fn finding_location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end_line) if end_line > finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

fn finding_verdict_label(finding: &Finding) -> String {
    match finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
    {
        Some("true_positive") => "tp",
        Some("false_positive") => "fp",
        Some("needs_review") => "review",
        Some("by_design") => "by-design",
        Some(other) => other,
        None => "untriaged",
    }
    .to_string()
}

fn finding_confidence_label(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| format!("{:.0}%", (triage.confidence.clamp(0.0, 1.0) * 100.0)))
        .unwrap_or_else(|| "-".to_string())
}

fn finding_cwe_label(finding: &Finding) -> String {
    extract_cwe(&finding.message)
        .or_else(|| extract_cwe(&finding.rule_id))
        .unwrap_or_else(|| "-".to_string())
}

fn extract_cwe(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    for (index, _) in upper.match_indices("CWE") {
        let mut rest = upper[index + 3..].chars();
        while matches!(rest.clone().next(), Some('-' | '_' | ' ' | ':')) {
            rest.next();
        }
        let digits = rest
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if !digits.is_empty() {
            return Some(format!("CWE-{digits}"));
        }
    }
    None
}

fn finding_source_label(finding: &Finding) -> String {
    if finding.rule_id.is_empty() || finding.rule_id.starts_with(&finding.tool) {
        finding.tool.clone()
    } else {
        format!("{}:{}", finding.tool, finding.rule_id)
    }
}

fn finding_evidence_preview(finding: &Finding) -> String {
    let lines = finding
        .message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if let Some(evidence) = lines.iter().find_map(|line| {
        line.strip_prefix("Evidence:")
            .or_else(|| line.strip_prefix("evidence:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }) {
        return evidence.to_string();
    }

    lines
        .iter()
        .copied()
        .find(|line| *line != finding.title)
        .unwrap_or_else(|| lines.first().copied().unwrap_or(&finding.title))
        .to_string()
}

fn render_throttle_banner(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(throttle) = &app.advisory.throttle else {
        return;
    };
    let text = fit(
        &format!("⚠ rate limit · {} · {}", throttle.source, throttle.message),
        area.width as usize,
    );
    frame.render_widget(Paragraph::new(Line::styled(text, theme::warn())), area);
}

fn render_plan_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(plan) = app.pending_plan.as_ref() else {
        return;
    };
    let active = plan
        .changes
        .iter()
        .enumerate()
        .filter(|(idx, _)| !app.plan_change_skipped(*idx))
        .count();
    let total = plan.changes.len();
    let cursor = app.plan_cursor_clamped();
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ PLAN · goal: {} · {active}/{total} active", plan.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(&format!("  summary: {}", plan.summary), area.width as usize),
        theme::primary(),
    ));
    for (idx, change) in plan.changes.iter().enumerate() {
        let skipped = app.plan_change_skipped(idx);
        let marker = if idx == cursor { ">" } else { " " };
        let toggle = if skipped { "[ ]" } else { "[x]" };
        let style = if skipped {
            theme::muted().add_modifier(Modifier::DIM)
        } else if idx == cursor {
            theme::success().add_modifier(Modifier::BOLD)
        } else {
            theme::success()
        };
        lines.push(Line::styled(
            fit(
                &format!("  {marker} {toggle} {}", change.label()),
                area.width as usize,
            ),
            style,
        ));
    }
    for note in &plan.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    lines.push(Line::styled(
        fit(
            "[j/k] move   [space] toggle   [y] apply active   [n] discard   /yes   /no",
            area.width as usize,
        ),
        theme::label(),
    ));
    render_lines(frame, area, lines);
}

fn render_cost_cap_halt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(halt) = app.advisory.budget_halt.as_ref() else {
        return;
    };
    let header = fit(
        &format!(
            "■ COST CAP HALT · spent ${:.4} / cap ${:.4}",
            halt.spent_usd, halt.limit_usd
        ),
        area.width as usize,
    );
    let actions = fit(
        "[c] continue past cap   [a] abort scan",
        area.width as usize,
    );
    let mut lines = vec![Line::styled(header, theme::danger())];
    if area.height > 1 {
        lines.push(Line::styled(actions, theme::warn()));
    }
    render_lines(frame, area, lines);
}

fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let left = if app.scan.as_ref().is_some_and(|scan| scan.running) {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            app.scan
                .as_ref()
                .map(scan_status)
                .unwrap_or_else(|| "idle".to_string()),
        ])
    } else if app.agent_chat.as_ref().is_some_and(|agent| agent.running) {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app
                .agent_chat
                .as_ref()
                .is_some_and(|agent| agent.abort_requested)
            {
                "agent: abort requested".to_string()
            } else {
                "agent: active".to_string()
            },
        ])
    } else if app.planner_running {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.plan_abort_requested {
                "plan: abort requested".to_string()
            } else {
                "plan: active".to_string()
            },
        ])
    } else if app.threat_worker_running {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.threat_abort_requested {
                "threats: abort requested".to_string()
            } else {
                "threats: active".to_string()
            },
        ])
    } else {
        join_segments(&[
            routing_mode_segment(app),
            app.target
                .as_ref()
                .map(|path| compact_target_path(&path.display().to_string()))
                .unwrap_or_else(|| "target:none".to_string()),
            if app.context_view.exists {
                "ctx: present".to_string()
            } else {
                "ctx: missing".to_string()
            },
            view_status_segment(app),
        ])
    };

    let mut right_segments = vec![findings_summary(&app.findings)];
    if app.ctrl_c_armed() {
        right_segments.insert(0, "Ctrl+C again to exit".to_string());
    }
    let right = join_segments(&right_segments);
    // Prefer the right segment when widths are tight: the top status strip
    // already shows mode + target + ctx, so on narrow terminals truncating
    // the duplicated left side keeps findings count + ctrl-c hint visible.
    let text = justify_prefer_right(left, right, area.width as usize);
    let style = if app.ctrl_c_armed() {
        theme::warn()
    } else {
        theme::primary()
    };
    frame.render_widget(Paragraph::new(Line::styled(text, style)), area);
}

fn justify_prefer_right(left: String, right: String, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if right.is_empty() {
        return fit(&left, width);
    }
    let right = fit(&right, width);
    let right_len = right.chars().count();
    if right_len + 1 >= width {
        return right;
    }
    let left_budget = width.saturating_sub(right_len + 1);
    let left = fit(&left, left_budget);
    let left_len = left.chars().count();
    let pad = width.saturating_sub(left_len + right_len);
    format!("{left}{}{}", " ".repeat(pad), right)
}

fn render_keybind_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    lines.push(Line::styled(
        theme::RULE_CHAR.repeat(area.width as usize),
        theme::subtle(),
    ));

    if area.height > 1 {
        lines.push(keybindings_line(app, area.width as usize));
    }

    render_lines(frame, area, lines);
}

/// Render the bottom keybind row to match `design/mockups/_shared.jsx::footer`:
///   `<key>` in accent, `<hint>` in muted, three-space separator between
///   pairs.  Keys flow left-to-right and the row is truncated, with an
///   actionable `help more` pointer if the full set won't fit.
fn keybindings_line(app: &ShellApp, width: usize) -> Line<'static> {
    const TAIL: &str = "help more";
    // Reserve enough headroom so the `help more` overflow chip always fits
    // (`   ` separator + the chip itself).
    let reserve = 3 + TAIL.chars().count();
    let bindings = keybindings(app);
    let bindings_len = bindings.len();

    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    let mut used = 1usize;
    let mut overflow = false;
    let mut placed = 0usize;

    for (i, (key, hint)) in bindings.into_iter().enumerate() {
        let pair = format!("{key} {hint}");
        let sep = if placed == 0 { 0 } else { 3 };
        let need = sep + pair.chars().count();
        // Last binding doesn't need to leave room for the tail chip — there
        // is nothing left to point at.
        let cap = if i + 1 == bindings_len {
            width.saturating_sub(1)
        } else {
            width.saturating_sub(reserve + 1)
        };
        if used + need > cap && placed > 0 {
            overflow = true;
            break;
        }
        if placed > 0 {
            spans.push(Span::raw("   "));
            used += 3;
        }
        spans.push(Span::styled(key.to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(hint.to_string(), theme::muted()));
        used += pair.chars().count();
        placed += 1;
    }

    if overflow {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("help".to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled("more".to_string(), theme::muted()));
    }

    Line::from(spans)
}

fn render_transcript(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    render_lines(frame, area, transcript_lines(app, area.height as usize));
}

fn render_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let prompt = match routing_mode(app) {
        RoutingMode::Run => "kuzushi/run> ".to_string(),
        RoutingMode::Agent => "kuzushi/agent> ".to_string(),
        RoutingMode::Plan => "kuzushi/plan> ".to_string(),
        RoutingMode::Module => app
            .focused_module
            .as_ref()
            .map(|module| format!("kuzushi/{module}> "))
            .unwrap_or_else(|| "kuzushi/module> ".to_string()),
        RoutingMode::Shell => "kuzushi> ".to_string(),
    };
    let segments = prompt_segments(&prompt, &app.input, app.cursor, area.width as usize, " ");
    let line = Line::from(vec![
        Span::styled(segments.prompt, theme::label()),
        Span::raw(segments.before_cursor),
        Span::styled(segments.cursor_text, theme::cursor_block()),
        Span::raw(segments.after_cursor),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let target = app
        .target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string());
    let focused_module = app.focused_module.as_deref().unwrap_or("—");
    let model = app.config.model.as_deref().unwrap_or("unconfigured");
    let cost_visible = app.session_cost_usd > 0.0;
    let cost_text = format_session_cost(app.session_cost_usd);

    // Build the strip as styled spans matching `design/mockups/_shared.jsx::statusStrip`:
    //   ` KUZUSHI  target <path>  ctx ✓ present  model <m>  module <m>  cost <c>`
    // - heading: bold white
    // - segment label: muted
    // - segment value: primary
    // - `✓` ctx checkmark when context snapshot exists: success
    // - module em-dash (no focused module): muted; focused module: accent
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    spans.push(Span::styled("KUZUSHI", theme::heading()));
    spans.push(Span::raw("  "));

    // target
    spans.push(Span::styled("target ", theme::muted()));
    spans.push(Span::styled(target, theme::primary()));
    spans.push(Span::raw("  "));

    // ctx
    spans.push(Span::styled("ctx ", theme::muted()));
    if app.context_view.exists {
        spans.push(Span::styled("✓ ", theme::success()));
        spans.push(Span::styled("present", theme::primary()));
    } else {
        spans.push(Span::styled("missing", theme::warn()));
    }
    spans.push(Span::raw("  "));

    // model
    spans.push(Span::styled("model ", theme::muted()));
    spans.push(Span::styled(model.to_string(), theme::primary()));
    spans.push(Span::raw("  "));

    // module
    spans.push(Span::styled("module ", theme::muted()));
    let module_style = if focused_module == "—" {
        theme::muted()
    } else {
        theme::accent()
    };
    spans.push(Span::styled(focused_module.to_string(), module_style));

    if cost_visible {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("cost ", theme::muted()));
        spans.push(Span::styled(cost_text, theme::primary()));
    }

    // Width safety: if the multi-span row would exceed the available width,
    // fall back to a single fitted line so right-edge segments don't drop
    // silently off-screen on narrow terminals.
    let total_chars: usize = spans
        .iter()
        .map(|span| span.content.chars().count())
        .sum();
    if total_chars + 1 > area.width as usize {
        let mut compact = vec![format!("target {}", spans.iter().nth(4).map(|s| s.content.to_string()).unwrap_or_default())];
        if app.context_view.exists {
            compact.push("ctx ✓ present".to_string());
        } else {
            compact.push("ctx missing".to_string());
        }
        compact.push(format!("model {model}"));
        compact.push(format!("module {focused_module}"));
        if cost_visible {
            compact.push(format!("cost {}", format_session_cost(app.session_cost_usd)));
        }
        let rest = fit(
            &join_segments(&compact),
            area.width.saturating_sub(9) as usize,
        );
        return vec![Line::from(vec![
            Span::styled("KUZUSHI", theme::heading()),
            Span::raw("  "),
            Span::styled(rest, theme::primary()),
        ])];
    }

    vec![Line::from(spans)]
}

fn transcript_lines(app: &ShellApp, visible: usize) -> Vec<Line<'static>> {
    if visible == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in &app.log {
        let body_lines = if line.body.is_empty() {
            vec![""]
        } else {
            line.body.lines().collect::<Vec<_>>()
        };
        for (index, body) in body_lines.into_iter().enumerate() {
            rows.push(transcript_line(&line.prefix, body, index > 0));
        }
    }
    let start = rows.len().saturating_sub(visible);
    rows.into_iter().skip(start).collect()
}

fn transcript_line(prefix: &str, body: &str, continuation: bool) -> Line<'static> {
    let (glyph, style, show_label) = transcript_glyph(prefix, continuation);
    let mut spans = vec![Span::styled(format!(" {glyph} "), style)];
    if show_label {
        spans.push(Span::styled(prefix.to_string(), theme::subtle()));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        body.to_string(),
        transcript_body_style(prefix),
    ));
    Line::from(spans)
}

fn transcript_glyph(prefix: &str, continuation: bool) -> (&'static str, Style, bool) {
    // Glyph + color mapping mirrors `design/mockups/_shared.jsx::logLine`:
    //   in:    ●  c-accent     (operator input echo)
    //   run:   ⏵  c-primary    (tool/module dispatch)
    //   ok:    ✓  c-success    (success)
    //   err:   ✗  c-danger     (failure)
    //   agent: ◆  c-accent     (LLM message)
    //   flow:  …  c-muted      (streaming/in-flight)
    //   find:  ▸  c-warn       (finding)
    //   log:   ·  c-subtle     (ambient/log)
    if continuation {
        return ("…", theme::muted(), false);
    }
    match prefix {
        ">" => ("●", theme::accent(), false),
        "tool" | "scan" | "run" | "resume" | "pause" => ("⏵", theme::primary(), true),
        "ok" | "success" | "done" => ("✓", theme::success(), true),
        "result" | "answer" | "agent" | "plan" | "threats" => ("◆", theme::accent(), true),
        "finding" | "open" | "title" | "triage" | "aliases" => ("▸", theme::warn(), true),
        "error" => ("✗", theme::danger(), true),
        "system" | "startup" | "first-run" | "help" | "view" | "module" | "prompt" | "tune"
        | "target" | "workspace" | "context" | "history" | "quickstart" | "auth" | "model"
        | "provider" | "backend" | "cost" | "load" | "runs" | "replay" | "trace" => {
            ("·", theme::muted(), true)
        }
        _ => ("·", theme::subtle(), true),
    }
}

fn transcript_body_style(prefix: &str) -> Style {
    match prefix {
        "error" => theme::danger(),
        "finding" | "open" => theme::warn(),
        "result" | "answer" | "agent" => theme::primary(),
        _ => Style::default(),
    }
}

fn keybindings(app: &ShellApp) -> Vec<(&'static str, &'static str)> {
    if app.scan.as_ref().is_some_and(|scan| scan.running) {
        let mut bindings = vec![(
            "Ctrl+C",
            if app.scan.as_ref().is_some_and(|scan| scan.abort_requested) {
                "arm exit"
            } else {
                "request abort"
            },
        )];
        push_view_keybindings(&mut bindings, app);
        bindings.extend([("findings", "list"), ("back", "home")]);
        return bindings;
    }
    if app.agent_chat.as_ref().is_some_and(|agent| agent.running)
        || app.planner_running
        || app.threat_worker_running
    {
        let abort_requested = app
            .agent_chat
            .as_ref()
            .is_some_and(|agent| agent.abort_requested)
            || app.plan_abort_requested
            || app.threat_abort_requested;
        return vec![
            (
                "Ctrl+C",
                if abort_requested {
                    "arm exit"
                } else {
                    "request abort"
                },
            ),
            ("back", "home"),
            ("history", "events"),
            ("model", "runtime"),
        ];
    }

    let mut bindings = match app.shell_view {
        ShellView::Catalog if !app.catalog_expanded => vec![
            ("modules", "browse"),
            ("use <id>", "focus module"),
            ("scan", "scan target"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Catalog => vec![
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("findings", "findings"),
            ("help", "help"),
        ],
        ShellView::Findings => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([("scan", "rescan"), ("back", "home"), ("Ctrl+C", "exit")]);
            bindings
        }
        ShellView::Finding => vec![
            ("back", "findings"),
            ("findings", "list"),
            ("scan", "rescan"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Threat(_) => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([
                ("threats edit", "edit"),
                ("back", "home"),
                ("Ctrl+C", "exit"),
            ]);
            bindings
        }
        ShellView::ModuleRun => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([("findings", "list"), ("back", "home"), ("Ctrl+C", "exit")]);
            bindings
        }
        ShellView::PromptsEditor => vec![
            ("prompt edit", "edit"),
            ("prompt show", "show"),
            ("back", "module"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Options(_) => vec![
            ("set key value", "set"),
            ("show advanced", "advanced"),
            ("show missing", "missing"),
            ("back", "module"),
        ],
        ShellView::Context => vec![
            ("context build", "build"),
            ("context status", "status"),
            ("context regen repo", "regen"),
            ("back", "module"),
        ],
        ShellView::Workspace => vec![
            ("workspace status", "status"),
            ("workspace export", "findings"),
            ("scan <target>", "select target"),
            ("back", "module"),
        ],
        ShellView::KnowledgeBase => vec![
            ("PgUp/PgDn", "scroll"),
            ("attach <path>", "attach"),
            ("detach <id>", "detach"),
            ("reparse <id>", "reparse"),
        ],
        ShellView::AgentChat => vec![
            ("ask <q>", "new question"),
            ("?text", "ask"),
            ("model", "runtime"),
            ("back", "home"),
        ],
        ShellView::History => vec![
            ("PgUp/PgDn", "scroll"),
            ("clear", "clear log"),
            ("show runs", "runs"),
            ("story", "story"),
        ],
        ShellView::Story => vec![
            ("history", "commands"),
            ("show runs", "runs"),
            ("replay <id>", "replay"),
            ("back", "home"),
        ],
        ShellView::Help => vec![
            // Mirrors `design/mockups/help.jsx` keybinds: highlight the
            // shell verbs that are always available so the help screen
            // doubles as a discovery surface.
            ("?<text>", "agent chat"),
            ("Tab", "complete"),
            ("Ctrl+R", "search history"),
            ("PgUp/PgDn", "scroll"),
            ("back", "catalog"),
        ],
        ShellView::Tools => vec![
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("options <tool>", "options"),
            ("back", "home"),
        ],
        _ => vec![
            ("Enter", "run command"),
            ("back", "home"),
            ("help", "help"),
            ("Ctrl+C", "exit"),
        ],
    };
    bindings.insert(0, ("Tab", "complete"));
    bindings
}

fn push_view_keybindings(bindings: &mut Vec<(&'static str, &'static str)>, app: &ShellApp) {
    for binding in app.view_keybindings() {
        if !bindings
            .iter()
            .any(|(hint, label)| *hint == binding.hint && *label == binding.label)
        {
            bindings.push((binding.hint, binding.label));
        }
    }
}

fn render_lines(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn detail(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key} "), theme::label()),
        Span::raw(value.to_string()),
    ])
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn divider(title: &str, width: u16) -> Line<'static> {
    // `design/mockups/_shared.jsx::sectionHeader` lays the rule out
    // left-aligned: ` ── LABEL ────...────`. The TUI used to center the
    // label between two rules, which read as a heavy decorative bar that
    // didn't match the lightweight muscle-memory feel of the mockups.
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

/// Catalog category divider that embeds the section blurb on the rule line:
///   `── OFFENSE find vulnerabilities by … ──────────`
/// Mirrors `catHead` in `design/mockups/catalog.jsx`.
fn category_divider(name: &str, blurb: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label = format!("{name} ");
    let blurb_text = format!("{blurb} ");
    let used = lead.chars().count() + label.chars().count() + blurb_text.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(blurb_text, theme::muted()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

fn module_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = if total < 72 { 14 } else { 22 };
    let gaps = 2;
    let description = total.saturating_sub(id + gaps).max(16);
    vec![id, description]
}

fn table_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    // Mockup column headers wear `c-label` (bold blue), see e.g.
    // `design/mockups/findings.jsx::heads` and `tools.jsx::heads`.
    Line::styled(table_text(values, widths), theme::label())
}

fn table_row(values: &[&str], widths: &[usize]) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("  "));
        }
        let style = if index == 0 {
            theme::accent()
        } else {
            Style::default()
        };
        spans.push(Span::styled(
            pad(value, widths.get(index).copied().unwrap_or(12)),
            style,
        ));
    }
    Line::from(spans)
}

fn table_text(values: &[&str], widths: &[usize]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| pad(value, widths.get(index).copied().unwrap_or(12)))
        .collect::<Vec<_>>()
        .join("  ")
}

fn row(values: &[String]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let style = if index == 0 {
                    theme::accent()
                } else {
                    Style::default()
                };
                Span::styled(format!("{}  ", value), style)
            })
            .collect::<Vec<_>>(),
    )
}

fn aligned_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .zip(widths.iter())
            .map(|(value, width)| {
                // c-label header per `design/mockups/_shared.jsx` headers.
                Span::styled(format!("{}  ", pad(value, *width)), theme::label())
            })
            .collect::<Vec<_>>(),
    )
}

fn aligned_row(values: &[String], widths: &[usize]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .zip(widths.iter())
            .enumerate()
            .map(|(index, (value, width))| {
                let style = if index == 0 {
                    theme::accent()
                } else {
                    Style::default()
                };
                Span::styled(format!("{}  ", pad(&fit(value, *width), *width)), style)
            })
            .collect::<Vec<_>>(),
    )
}

fn pipeline_row(symbol: &str, label: &str, detail: &str) -> Line<'static> {
    let style = match symbol {
        "✓" => theme::success(),
        "→" | "⏵" => theme::accent(),
        _ => theme::subtle(),
    };
    Line::from(vec![
        Span::styled(format!("{symbol} "), style),
        Span::styled(pad(label, 24), theme::label()),
        Span::styled(detail.to_string(), theme::muted()),
    ])
}

fn threat_nav(active: ThreatView) -> Line<'static> {
    let items = [
        (ThreatView::Dfd, "1 DFD"),
        (ThreatView::Stride, "2 STRIDE"),
        (ThreatView::Stories, "3 STORIES"),
        (ThreatView::Scope, "4 SCOPE"),
        (ThreatView::Summary, "5 SUMMARY"),
    ];
    let mut spans = Vec::new();
    for (index, (view, label)) in items.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        let style = if *view == active {
            theme::selection()
        } else {
            theme::muted()
        };
        spans.push(Span::styled(*label, style));
    }
    Line::from(spans)
}

fn blank() -> Line<'static> {
    Line::raw("")
}

fn muted(value: &str) -> Line<'static> {
    styled(value, theme::muted())
}

fn styled(value: &str, style: Style) -> Line<'static> {
    Line::styled(value.to_string(), style)
}

fn indent(line: Line<'static>, spaces: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(spaces))];
    spans.extend(line.spans);
    Line::from(spans)
}

fn next_action_line(text: &str, width: usize) -> Line<'static> {
    let available = width.saturating_sub(8);
    let fitted = fit(text, available);
    // Mirror the mockup's c-warn / c-primary / c-muted split for the catalog
    // NEXT line (see `design/mockups/catalog.jsx`):
    //   ▸ NEXT  Run sast:scan against ~/work/acme-checkout — never run here
    //   ----    -------------------------------------- --- -----------------
    //   warn    primary                                     muted
    // Use the em-dash (` — `) as the muted-suffix split if present so the
    // ambient context (run history, finding count) reads softer than the
    // imperative action.
    let mut spans: Vec<Span<'static>> = vec![Span::styled("▸ NEXT ", theme::warn())];
    if let Some(idx) = fitted.find(" — ") {
        let (head, tail) = fitted.split_at(idx);
        spans.push(Span::styled(head.to_string(), theme::primary()));
        spans.push(Span::styled(tail.to_string(), theme::muted()));
    } else {
        spans.push(Span::styled(fitted, theme::primary()));
    }
    Line::from(spans)
}

/// Context-aware NEXT hint for the catalog view. Picks the most relevant
/// next action based on whether context is built, target is selected, and
/// findings exist.
fn catalog_next_hint(app: &ShellApp) -> String {
    if !app.context_view.exists {
        return "Build the context snapshot with `context build` so SAST has structure to walk."
            .to_string();
    }
    let critical_count = app
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    if critical_count > 0 {
        if let Some((alias, _)) = sorted_finding_aliases(&app.findings).into_iter().next() {
            return format!(
                "Drill in: `open {alias}` for the highest-severity finding · `findings` for the list."
            );
        }
    }
    if !app.findings.is_empty() {
        return format!(
            "{} finding(s) waiting · `findings` to triage · `threats build` for STRIDE.",
            app.findings.len()
        );
    }
    app.first_finding_hint()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressKind {
    Done,
    Active,
    Failing,
}

impl ProgressKind {
    fn fill_style(self) -> Style {
        match self {
            ProgressKind::Done => theme::success(),
            ProgressKind::Active => theme::warn(),
            ProgressKind::Failing => theme::danger(),
        }
    }

    fn status_style(self) -> Style {
        self.fill_style()
    }
}

/// Render a progress bar matching `design/mockups/sast.jsx::bar()`:
///
/// ```text
///    semgrep              [████████████████████░░░░]  612/612   done · 18 raw hits
/// ```
fn progress_bar_line(
    label: &str,
    done: usize,
    total: usize,
    status: &str,
    kind: ProgressKind,
) -> Line<'static> {
    let bar_width: usize = 24;
    let filled = if total == 0 {
        0
    } else {
        let raw = (bar_width as f64 * done as f64 / total as f64).round() as usize;
        raw.min(bar_width)
    };
    let empty = bar_width - filled;
    let count = format!("{done}/{total}");
    let count = format!("{:>7}", count);

    Line::from(vec![
        Span::raw("   "),
        Span::styled(pad(label, 20), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(filled), kind.fill_style()),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(count, theme::muted()),
        Span::raw("  "),
        Span::styled(status.to_string(), kind.status_style()),
    ])
}

/// Section header matching `design/mockups/_shared.jsx::sectionHeader()`:
/// uppercase bold heading on the left, subtle dash filler on the right.
fn section_header_line(label: &str, width: u16) -> Line<'static> {
    let text = label.to_uppercase();
    let total = width as usize;
    let used = text.chars().count() + 2;
    let dashes = total.saturating_sub(used).max(2);
    Line::from(vec![
        Span::styled(format!("{text}  "), theme::heading()),
        Span::styled("─".repeat(dashes), theme::subtle()),
    ])
}

/// STRIDE rollup row matching `design/mockups/threat-model.jsx`:
///
/// ```text
///    [ S ] Spoofing         2 issues  · jwt without aud-claim, mailgun cname dangling
/// ```
fn stride_row(
    letter: &str,
    severity: Severity,
    category: &str,
    count: usize,
    description: &str,
    width: u16,
) -> Line<'static> {
    let total = width as usize;
    let used = 3 + 3 + 1 + 16 + 4 + 10;
    let desc_w = total.saturating_sub(used).max(8);
    let issues_label = if count == 1 { "issue" } else { "issues" };
    let mut spans = vec![
        Span::raw("   "),
        Span::styled(format!(" {letter} "), theme::severity(severity)),
        Span::raw(" "),
        Span::styled(pad(category, 16), theme::muted()),
        Span::styled(format!("{count} "), theme::primary()),
        Span::styled(format!("{issues_label}"), theme::muted()),
    ];
    if !description.is_empty() {
        spans.push(Span::styled("  · ", theme::muted()));
        spans.push(Span::styled(fit(description, desc_w), theme::muted()));
    }
    Line::from(spans)
}

/// Returns the canonical 6-row STRIDE rollup matching the design fixture.
/// Used as a fallback when no `.kuzushi/threat-model.json` is present.
fn stride_rollup_rows() -> Vec<(&'static str, Severity, &'static str, usize, String)> {
    vec![
        (
            "S",
            Severity::High,
            "Spoofing",
            2,
            "jwt without aud-claim, mailgun cname dangling".to_string(),
        ),
        (
            "T",
            Severity::Medium,
            "Tampering",
            1,
            "worker pool reads unsigned amqp messages".to_string(),
        ),
        ("R", Severity::Low, "Repudiation", 0, String::new()),
        (
            "I",
            Severity::Critical,
            "Info-disclosure",
            3,
            "plaintext PII at db→s3 boundary, debug logs".to_string(),
        ),
        (
            "D",
            Severity::Medium,
            "DoS",
            1,
            "no rate-limit on /checkout/confirm".to_string(),
        ),
        (
            "E",
            Severity::High,
            "Elev-of-priv",
            1,
            "admin subdomain shares jwt secret with api".to_string(),
        ),
    ]
}

/// Canonical 10-row ASCII DFD matching `design/mockups/threat-model.jsx`.
/// 5 boxed nodes + 2 annotated edges (jwt, plaintext PII).
fn dfd_canonical_lines() -> Vec<Line<'static>> {
    let sub = theme::subtle();
    let acc = theme::accent();
    let mut_ = theme::muted();
    let warn = theme::warn();
    vec![
        Line::from(vec![
            Span::raw("     "),
            Span::styled(
                "┌────────────┐         ┌─────────────┐         ┌──────────────┐",
                sub,
            ),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("│ ", sub),
            Span::styled("  user    ", acc),
            Span::styled("│  https  │ ", sub),
            Span::styled(" api edge  ", acc),
            Span::styled("│   sql   │ ", sub),
            Span::styled("  postgres   ", acc),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("│ ", sub),
            Span::styled("  browser ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled("  nginx    ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled("  primary db ", mut_),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled(
                "└────────────┘         └──────┬──────┘         └──────┬───────┘",
                sub,
            ),
        ]),
        Line::from(vec![
            Span::raw("                                       "),
            Span::styled("│ ", sub),
            Span::styled("jwt", mut_),
            Span::raw("                    "),
            Span::styled("│ ", sub),
            Span::styled("plaintext PII", warn),
        ]),
        Line::from(vec![
            Span::raw("                                       "),
            Span::styled("▼", sub),
            Span::raw("                       "),
            Span::styled("▼", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("┌──────────────┐         ┌──────────────┐", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("│ ", sub),
            Span::styled(" worker pool  ", acc),
            Span::styled("│  amqp   │ ", sub),
            Span::styled(" s3 (us-east) ", acc),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("│ ", sub),
            Span::styled(" rabbitmq cli ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled(" invoices/    ", mut_),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("└──────────────┘         └──────────────┘", sub),
        ]),
    ]
}

/// Extract `(id, node_type, trust_zone)` triples from `dfd.nodes` if present.
fn dfd_nodes_from_doc(doc: &serde_json::Value) -> Option<Vec<(String, String, String)>> {
    let nodes = doc.get("dfd")?.get("nodes")?.as_array()?;
    if nodes.is_empty() {
        return None;
    }
    let rows = nodes
        .iter()
        .filter_map(|n| {
            let id = n.get("id").and_then(|v| v.as_str())?.to_string();
            let node_type = n
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("node")
                .to_string();
            let zone = n
                .get("trustZone")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, node_type, zone))
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}

/// Try to load the persisted threat model for the active workspace target.
/// Returns `None` if the file doesn't exist or is empty/null.
fn current_threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    let cwd = app
        .target
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let doc = kuzushi_core::load_persistent_threat_model(&cwd)?;
    if doc.is_null() {
        return None;
    }
    Some(doc)
}

/// Compute the STRIDE rollup from a persisted threat model document.
/// Returns `None` if the document has no `threats` array or it's empty.
fn stride_rollup_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<(&'static str, Severity, &'static str, usize, String)>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let cats: [(&'static str, &'static str, &'static str); 6] = [
        ("S", "spoofing", "Spoofing"),
        ("T", "tampering", "Tampering"),
        ("R", "repudiation", "Repudiation"),
        ("I", "information-disclosure", "Info-disclosure"),
        ("D", "denial-of-service", "DoS"),
        ("E", "elevation-of-privilege", "Elev-of-priv"),
    ];
    let mut rows = Vec::with_capacity(6);
    for (letter, key, label) in cats {
        let matching: Vec<&serde_json::Value> = threats
            .iter()
            .filter(|t| {
                t.get("category")
                    .and_then(|c| c.as_str())
                    .map(|c| c.to_lowercase().replace('_', "-"))
                    .as_deref()
                    == Some(key)
            })
            .collect();
        let count = matching.len();
        let severity = matching
            .iter()
            .map(|t| {
                t.get("impact")
                    .and_then(|s| s.as_str())
                    .map(impact_to_severity)
                    .unwrap_or(Severity::Medium)
            })
            .max_by_key(|s| severity_rank(*s))
            .unwrap_or(Severity::Low);
        let description = matching
            .iter()
            .filter_map(|t| {
                t.get("title")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            })
            .take(2)
            .collect::<Vec<_>>()
            .join(", ");
        rows.push((letter, severity, label, count, description));
    }
    Some(rows)
}

/// `(id, severity, title, attack_vector, location)` — one attacker story.
type StoryRow = (String, Severity, String, String, String);

/// Extract attacker stories from the persisted threat model. Each `threats[]`
/// entry becomes one story, sorted by impact severity (highest first).
fn stories_from_doc(doc: &serde_json::Value) -> Option<Vec<StoryRow>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut rows: Vec<StoryRow> = threats
        .iter()
        .filter_map(|t| {
            let id = t.get("id").and_then(|v| v.as_str())?.to_string();
            let severity = t
                .get("impact")
                .and_then(|v| v.as_str())
                .map(impact_to_severity)
                .unwrap_or(Severity::Medium);
            let title = t
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("untitled")
                .to_string();
            let attack = t
                .get("attackVector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let location = t
                .get("affectedFiles")
                .and_then(|v| v.as_array())
                .and_then(|files| files.first())
                .map(|f| {
                    let path = f.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
                    let line = f.get("startLine").and_then(|v| v.as_u64()).unwrap_or(0);
                    if path.is_empty() {
                        String::new()
                    } else if line == 0 {
                        path.to_string()
                    } else {
                        format!("{path}:{line}")
                    }
                })
                .unwrap_or_default();
            Some((id, severity, title, attack, location))
        })
        .collect();
    rows.sort_by_key(|(_, sev, _, _, _)| std::cmp::Reverse(severity_rank(*sev)));
    Some(rows)
}

/// Fixture matching the canonical 4 attacker stories used when no real
/// threat model is loaded.
fn canonical_stories_fixture() -> Vec<StoryRow> {
    vec![
        (
            "T-001".to_string(),
            Severity::Critical,
            "sql injection via order_id concatenation".to_string(),
            "POST /orders/<id>".to_string(),
            "apps/api/orders.rs:142".to_string(),
        ),
        (
            "T-002".to_string(),
            Severity::Critical,
            "prompt injection sink reads user body".to_string(),
            "user message → llm context".to_string(),
            "apps/web/agents/concierge.ts:88".to_string(),
        ),
        (
            "T-003".to_string(),
            Severity::High,
            "jwt verify accepts alg=none".to_string(),
            "forged Authorization header".to_string(),
            "apps/api/auth/jwt.rs:54".to_string(),
        ),
        (
            "T-004".to_string(),
            Severity::High,
            "shell exec from cron payload".to_string(),
            "scheduled job pulls untrusted task".to_string(),
            "jobs/worker.py:213".to_string(),
        ),
    ]
}

/// `(severity, label, items)` — one criticality bucket of threat titles.
type ScopeBucket = (Severity, &'static str, Vec<String>);

/// Bucket threats from the persisted model by impact severity.
fn scope_buckets_from_doc(doc: &serde_json::Value) -> Option<Vec<ScopeBucket>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut buckets: Vec<ScopeBucket> = vec![
        (Severity::Critical, "critical", Vec::new()),
        (Severity::High, "high", Vec::new()),
        (Severity::Medium, "medium", Vec::new()),
        (Severity::Low, "low", Vec::new()),
    ];
    for t in threats {
        let severity = t
            .get("impact")
            .and_then(|v| v.as_str())
            .map(impact_to_severity)
            .unwrap_or(Severity::Medium);
        let title = t
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("untitled")
            .to_string();
        if let Some((_, _, items)) = buckets.iter_mut().find(|(sev, _, _)| *sev == severity) {
            items.push(title);
        }
    }
    Some(buckets)
}

/// Fixture used when no real threat model is loaded — matches the canonical
/// design content.
fn canonical_scope_buckets() -> Vec<ScopeBucket> {
    vec![
        (
            Severity::Critical,
            "critical",
            vec![
                "sql injection via order_id concatenation".to_string(),
                "prompt injection sink reads user body".to_string(),
            ],
        ),
        (
            Severity::High,
            "high",
            vec![
                "jwt verify accepts alg=none".to_string(),
                "shell exec from cron payload".to_string(),
                "path traversal in /assets/<file>".to_string(),
            ],
        ),
        (
            Severity::Medium,
            "medium",
            vec![
                "open redirect on /login?next=".to_string(),
                "csrf token not bound to session".to_string(),
                "unbounded regex on /search".to_string(),
            ],
        ),
        (
            Severity::Low,
            "low",
            vec![
                "cors allows null origin".to_string(),
                "cookie set without SameSite".to_string(),
                "console.log of req.body in handler".to_string(),
            ],
        ),
    ]
}

fn impact_to_severity(value: &str) -> Severity {
    match value.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

/// One-line finding row matching `design/mockups/sast.jsx::finding()`:
///
/// ```text
///  F-0001  CRITICAL  sql injection via order_id concatenation       apps/api/orders.rs:142
/// ```
fn compact_finding_row(
    alias: &str,
    severity: Severity,
    name: &str,
    location: &str,
    width: u16,
) -> Line<'static> {
    let alias_w = 8;
    let sev_w = 9;
    let used = 1 + alias_w + 2 + sev_w;
    let total = (width as usize).saturating_sub(used);
    let location_w = location.chars().count().min(total.saturating_sub(2)).max(8);
    let name_w = total.saturating_sub(location_w + 2).max(12);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(pad(alias, alias_w), theme::accent()),
        Span::raw("  "),
        Span::styled(
            pad(&severity.as_str().to_uppercase(), sev_w),
            theme::severity(severity),
        ),
        Span::styled(pad(&fit(name, name_w), name_w), theme::primary()),
        Span::styled("  ", Style::default()),
        Span::styled(fit(location, location_w), theme::muted()),
    ])
}

fn catalog_module_row(
    id: &str,
    description: &str,
    focused: bool,
    widths: &[usize],
) -> Line<'static> {
    let id_width = widths.first().copied().unwrap_or(16);
    let description_width = widths.get(1).copied().unwrap_or(24);
    if focused {
        return Line::from(vec![
            Span::styled("▌ ", theme::accent()),
            Span::styled(
                format!(
                    "{}  {}",
                    pad(id, id_width),
                    pad(description, description_width)
                ),
                theme::selection(),
            ),
        ]);
    }
    Line::from(vec![
        Span::raw("  "),
        Span::styled(pad(id, id_width), theme::primary()),
        Span::raw("  "),
        Span::styled(pad(description, description_width), theme::muted()),
    ])
}

fn tool_console_row(name: &str, description: &str, headless: bool, width: u16) -> Line<'static> {
    let status = if headless { "headless" } else { "interactive" };
    let name_width = if width < 80 { 22 } else { 30 };
    let used = 4 + name_width + status.len() + 6;
    Line::from(vec![
        Span::styled(" ⏵ ", theme::subtle()),
        Span::styled(pad(name, name_width), theme::accent()),
        Span::styled(format!(" {status} "), theme::muted()),
        Span::styled(
            fit(description, (width as usize).saturating_sub(used).max(12)),
            theme::primary(),
        ),
    ])
}

fn module_playbook_lines(module_id: &str, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![divider("NEXT", width)];
    let (run, inspect) = match module_id {
        "context" => (
            "run build to write .kuzushi/context-snapshot.json",
            "context status · context regen repo",
        ),
        "recon" => (
            "run nmap, subdomain, or http-fingerprint with a target",
            "workspace · findings · use threat-model",
        ),
        "threat-model" => (
            "run build to refresh STRIDE / DFD artifacts",
            "threats summary · threats edit · threats regen",
        ),
        "sast" => (
            "run . or scan to launch the umbrella scanner",
            "tasks · findings · use triage",
        ),
        "carlini-threat-hunt" => (
            "run . after threat-model:build to start adversarial actor hunts",
            "show trace · findings · use verify",
        ),
        "agentic-sast" => (
            "run scan to start dataflow and variant hunting agents",
            "findings · show trace · use verify",
        ),
        _ => (
            "run . to dispatch the primary tool for this module",
            "options . · prompts · tune · back",
        ),
    };
    lines.push(transcript_line("tool", &fit(run, width as usize), false));
    lines.push(transcript_line(
        "help",
        &fit(inspect, width as usize),
        false,
    ));
    lines
}

fn catalog_module_category(id: &str, kind: ModuleKind) -> &'static str {
    match id {
        "semgrep"
        | "sast"
        | "codeql"
        | "agentic-sast"
        | "carlini-threat-hunt"
        | "secret-scan"
        | "iac-scan"
        | "dep-hygiene"
        | "taint-iris"
        | "taint-iris-next"
        | "systems-hunt"
        | "chrome-rce"
        | "prompt-armor"
        | "vuln-scout"
        | "tob" => "OFFENSE",
        "context" | "context-lite" | "recon" | "threat-model" | "randori" | "x-ray" | "ndiff"
        | "workspace" => "INTEL",
        "triage" | "verify" | "patch" | "findings" => "DEFENSE",
        _ => module_category(kind).0,
    }
}

fn module_category(kind: ModuleKind) -> (&'static str, &'static str) {
    match kind {
        ModuleKind::Offense | ModuleKind::Scan => {
            ("OFFENSE", "hunt vulnerabilities and prove exploitability")
        }
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => {
            ("INTEL", "map target context and workspace state")
        }
        ModuleKind::Governance | ModuleKind::Config | ModuleKind::Catalog => (
            "GOVERNANCE",
            "configuration, inventory, and operator controls",
        ),
        ModuleKind::Defense | ModuleKind::Findings | ModuleKind::Triage => {
            ("DEFENSE", "prioritize, triage, and remediate findings")
        }
        ModuleKind::Internal => ("GOVERNANCE", "internal orchestration"),
    }
}

fn module_category_blurb(category: &str) -> (&'static str, &'static str) {
    match category {
        "OFFENSE" => (
            "OFFENSE",
            "find vulnerabilities by scanning code, dependencies, and runtime surface",
        ),
        "INTEL" => (
            "INTEL",
            "build context, recon, and threat model the operator reads first",
        ),
        "GOVERNANCE" => ("GOVERNANCE", "configuration, allowlists, and audit trails"),
        "DEFENSE" => ("DEFENSE", "triage, verify, and patch emitted findings"),
        _ => ("OTHER", "loaded module surfaces"),
    }
}

fn scan_status(scan: &ScanPanelState) -> String {
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
const SPINNER_FRAMES: &[&str] = &["⠿", "⠾", "⠷", "⠯", "⠟", "⠻"];

fn run_state_glyph(scan: Option<&ScanPanelState>, tick: usize) -> &'static str {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => "✗",
        Some(scan) if scan.running => SPINNER_FRAMES[tick % SPINNER_FRAMES.len()],
        Some(scan) if scan.error.is_some() => "✗",
        Some(_) => "✓",
        None => "●",
    }
}

fn run_state_style(scan: Option<&ScanPanelState>) -> Style {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => theme::warn(),
        Some(scan) if scan.running => theme::warn(),
        Some(scan) if scan.error.is_some() => theme::danger(),
        Some(_) => theme::success(),
        None => theme::accent(),
    }
}

fn view_status_segment(app: &ShellApp) -> String {
    match &app.shell_view {
        ShellView::Catalog => app
            .focused_module
            .clone()
            .unwrap_or_else(|| "catalog".to_string()),
        ShellView::Module => app
            .focused_module
            .clone()
            .unwrap_or_else(|| "module".to_string()),
        ShellView::ModuleRun => app
            .focused_module
            .as_ref()
            .map(|module| format!("{module}/run"))
            .unwrap_or_else(|| "run".to_string()),
        ShellView::Findings => "findings".to_string(),
        ShellView::Finding => "finding".to_string(),
        ShellView::Tune => "tune".to_string(),
        ShellView::Threat(view) => format!(
            "threats:{}",
            match view {
                ThreatView::Dfd => "dfd",
                ThreatView::Stride => "stride",
                ThreatView::Stories => "stories",
                ThreatView::Scope => "scope",
                ThreatView::Summary => "summary",
            }
        ),
        ShellView::ThreatEditor => "threats:edit".to_string(),
        ShellView::PromptsEditor => "prompts".to_string(),
        ShellView::ActorDetail(index) => format!("actor:{}", index + 1),
        ShellView::Runs => "runs".to_string(),
        ShellView::Replay(_) => "replay".to_string(),
        ShellView::Trace(_) => "trace".to_string(),
        ShellView::Help => "help".to_string(),
        ShellView::Quickstart => "quickstart".to_string(),
        ShellView::Config => "config".to_string(),
        ShellView::Tools => "tools".to_string(),
        ShellView::Options(view) => format!("options[{}]", view.tool_name),
        ShellView::SastTasks => "tasks".to_string(),
        ShellView::Context => "context".to_string(),
        ShellView::Workspace => "workspace".to_string(),
        ShellView::KnowledgeBase => "kb".to_string(),
        ShellView::AgentChat => "agent".to_string(),
        ShellView::History => "history".to_string(),
        ShellView::Story => "story".to_string(),
    }
}

fn findings_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    let mut parts = vec![format!("{} findings", findings.len())];
    if counts.critical > 0 {
        parts.push(format!("{} critical", counts.critical));
    }
    if counts.high > 0 {
        parts.push(format!("{} high", counts.high));
    }
    if counts.medium > 0 {
        parts.push(format!("{} medium", counts.medium));
    }
    parts.join(" / ")
}

fn findings_count_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    if counts.critical > 0 {
        return format!("{} findings ({} critical)", findings.len(), counts.critical);
    }
    if counts.high > 0 {
        return format!("{} findings ({} high)", findings.len(), counts.high);
    }
    if counts.medium > 0 {
        return format!("{} findings ({} medium)", findings.len(), counts.medium);
    }
    format!("{} findings", findings.len())
}

fn join_segments(values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(theme::STATUS_SEPARATOR)
}

fn compact_target_path(value: &str) -> String {
    let trimmed = value.trim_end_matches('/');
    let name = trimmed
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(trimmed);
    if name.is_empty() {
        "target:/".to_string()
    } else {
        format!("./{name}")
    }
}

fn short(value: &str) -> String {
    value.chars().take(8).collect()
}

fn short_sentence(value: &str, max_chars: usize) -> String {
    let first = value.split('.').next().unwrap_or(value).trim();
    fit(first, max_chars)
}

/// Compact dollar-amount format for the header. Sub-cent values keep four
/// decimals (e.g. "$0.0042"); larger values drop to two so a long-running
/// session doesn't read "$12.4567" and waste header cells.
fn format_session_cost(usd: f64) -> String {
    if usd < 0.01 {
        format!("${usd:.4}")
    } else if usd < 100.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.0}")
    }
}

fn fit(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    for raw_line in value.lines() {
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            let mut pending = word.to_string();
            while !pending.is_empty() {
                let pending_len = pending.chars().count();
                let current_len = current.chars().count();
                if current_len == 0 {
                    if pending_len <= width {
                        current = pending;
                        break;
                    }
                    let (head, tail) = split_at_char_count(&pending, width);
                    lines.push(head);
                    pending = tail;
                } else if current_len + 1 + pending_len <= width {
                    current.push(' ');
                    current.push_str(&pending);
                    break;
                } else {
                    lines.push(current);
                    current = String::new();
                }
            }
        }
        if !current.is_empty() {
            lines.push(current);
        } else if raw_line.is_empty() {
            lines.push(String::new());
        }
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn split_at_char_count(value: &str, count: usize) -> (String, String) {
    if count == 0 {
        return (String::new(), value.to_string());
    }
    let split_index = value
        .char_indices()
        .nth(count)
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    (
        value[..split_index].to_string(),
        value[split_index..].to_string(),
    )
}

fn pad(value: &str, width: usize) -> String {
    let value = fit(value, width);
    let padding = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(padding))
}

fn value_width(area: Rect, used: usize) -> usize {
    (area.width as usize).saturating_sub(used).max(12)
}

fn options_filter_label(filter: crate::app::OptionsFilter) -> &'static str {
    match filter {
        crate::app::OptionsFilter::Standard => "standard",
        crate::app::OptionsFilter::Advanced => "advanced",
        crate::app::OptionsFilter::Missing => "missing required",
    }
}

fn option_visible(
    spec: &OptionSpec,
    filter: crate::app::OptionsFilter,
    has_stored_value: bool,
) -> bool {
    match filter {
        crate::app::OptionsFilter::Standard => !spec.advanced && !spec.evasion,
        crate::app::OptionsFilter::Advanced => spec.advanced || spec.evasion,
        crate::app::OptionsFilter::Missing => {
            spec.required && !has_stored_value && spec.default.is_none()
        }
    }
}

fn option_type_label(option_type: OptionType) -> &'static str {
    match option_type {
        OptionType::String => "string",
        OptionType::Bool => "bool",
        OptionType::Int => "int",
        OptionType::Float => "float",
        OptionType::Path => "path",
        OptionType::Enum => "enum",
        OptionType::StringList => "list",
    }
}

fn option_description(spec: &OptionSpec) -> String {
    if spec.choices.is_empty() {
        spec.description.clone()
    } else {
        format!("{} Choices: {}.", spec.description, spec.choices.join("|"))
    }
}

fn format_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

fn option_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let option = if total < 80 { 14 } else { 16 };
    let value = if total < 80 { 10 } else { 12 };
    let default = if total < 80 { 8 } else { 10 };
    let required = if total < 80 { 5 } else { 7 };
    let kind = 6;
    let gaps = 10;
    let description = total
        .saturating_sub(option + value + default + required + kind + gaps)
        .max(12);
    vec![option, value, default, required, kind, description]
}

fn sast_task_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 5;
    let id = if total < 88 { 20 } else { 24 };
    let cost = 5;
    let scan = if total < 88 { 14 } else { 18 };
    let gaps = 8;
    let notes = total
        .saturating_sub(state + id + cost + scan + gaps)
        .max(16);
    vec![state, id, cost, scan, notes]
}

#[derive(Debug)]
struct PromptSegments {
    prompt: String,
    before_cursor: String,
    cursor_text: String,
    after_cursor: String,
}

fn prompt_segments(
    prompt: &str,
    input: &str,
    cursor_index: usize,
    columns: usize,
    cursor_glyph: &str,
) -> PromptSegments {
    let width = columns.max(1);
    let min_editor_width = 2.min(width);
    let fitted_prompt = fit_prompt(prompt, width.saturating_sub(min_editor_width));
    let editor_width = width.saturating_sub(fitted_prompt.chars().count()).max(1);

    let input_chars = input.chars().collect::<Vec<_>>();
    let cursor = cursor_index.min(input_chars.len());
    let mut visual_chars = input_chars.clone();
    let cursor_text = if cursor < visual_chars.len() {
        visual_chars[cursor].to_string()
    } else {
        visual_chars.push(cursor_glyph.chars().next().unwrap_or(' '));
        cursor_glyph.to_string()
    };

    let visual_len = visual_chars.len();
    let start = prompt_window_start(visual_len, cursor, editor_width);
    let end = (start + editor_width).min(visual_len);
    let visible = &visual_chars[start..end];
    let visible_cursor = cursor
        .saturating_sub(start)
        .min(visible.len().saturating_sub(1));

    PromptSegments {
        prompt: fitted_prompt,
        before_cursor: visible[..visible_cursor].iter().collect(),
        cursor_text,
        after_cursor: visible[visible_cursor.saturating_add(1)..].iter().collect(),
    }
}

fn fit_prompt(prompt: &str, max_columns: usize) -> String {
    if max_columns == 0 {
        return String::new();
    }
    if prompt.chars().count() <= max_columns {
        return prompt.to_string();
    }
    if max_columns <= 4 {
        return prompt.chars().take(max_columns).collect();
    }

    let suffix = if prompt.ends_with("> ") { "> " } else { "" };
    let suffix_width = suffix.chars().count();
    let body_columns = max_columns.saturating_sub(suffix_width);
    if body_columns <= 3 {
        return prompt.chars().take(max_columns).collect();
    }
    format!(
        "{}...{}",
        prompt
            .chars()
            .take(body_columns.saturating_sub(3))
            .collect::<String>(),
        suffix
    )
}

fn prompt_window_start(line_len: usize, cursor_index: usize, width: usize) -> usize {
    if line_len <= width {
        return 0;
    }
    let max_start = line_len.saturating_sub(width);
    let cursor_margin = width.saturating_sub(1) / 2;
    max_start.min(cursor_index.saturating_sub(cursor_margin))
}

#[derive(Debug, Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
                Severity::Unknown => {}
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use kuzushi_core::{
        Finding, OptionScope, OptionTarget, ScanCancellation, Severity, TriageOutcome,
        TriageVerdict, V2Config,
    };
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::Terminal;

    use super::*;

    #[test]
    fn renders_ink_style_shell_without_box_dashboard() {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ShellApp::new(V2Config::default(), None);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        // Catalog title no longer repeats "kuzushi shell" (the prompt + the
        // top header already identify the shell). Verify the new
        // "KUZUSHI · CATALOG · N modules" signal is present, and the prompt
        // sigil + keybind chips still render.
        assert!(rendered.contains("KUZUSHI · CATALOG"));
        assert!(rendered.contains("modules"));
        assert!(rendered.contains("kuzushi>"));
        assert!(rendered.contains("Tab complete"));
        // The keybind footer now matches `design/mockups/_shared.jsx::footer`,
        // which renders unbracketed pairs. The `modules` keybind (Ratatui
        // catalog default) is still in the row — just without `[ ]` chrome.
        assert!(rendered.contains("modules browse"));
        assert!(!rendered.contains("command log"));
        assert!(!rendered.contains("┌"));
        assert!(!rendered.contains("v2"));
    }

    #[test]
    fn catalog_first_run_state_names_real_first_finding_commands() {
        let backend = TestBackend::new(80, 16);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ShellApp::new(V2Config::default(), None);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("First finding"));
        assert!(rendered.contains("scan ."));
        assert!(rendered.contains("findings"));
        assert!(rendered.contains("quickstart"));
        assert!(!rendered.contains("./repo"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_selected_finding_detail() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            8,
            Some(8),
            Severity::High,
            "dangerous sink",
        );
        app.findings = vec![finding.clone()];
        app.selected_finding = Some(finding);
        app.shell_view = ShellView::Finding;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("dangerous sink"));
        assert!(rendered.contains("alias"));
        assert!(rendered.contains("F-0001"));
        assert!(rendered.contains("fingerprint"));
    }

    #[test]
    fn renders_dense_findings_rows_at_80_columns() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut confirmed = Finding::new_semgrep(
            "typescript.express.sql-injection",
            "src/controllers/admin_search.ts",
            117,
            Some(119),
            Severity::High,
            "SQL injection in admin search\nEvidence: req.query.q flows into db.query without a guard\nCWE: CWE-89",
        );
        confirmed.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.91,
            rationale: "source and sink are linked in the same handler".to_string(),
            cost_usd: 0.0,
        });
        let untriaged = Finding::new_tool(
            "codeql",
            "js/path-injection",
            "src/files.ts",
            22,
            None,
            Severity::Medium,
            "Path traversal candidate\nEvidence: filename reaches fs.readFile",
        );
        app.findings = vec![confirmed, untriaged];
        app.shell_view = ShellView::Findings;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let rendered = format!("{:?}", buffer);

        for expected in [
            // Section header replaces the old column-name row.
            "FINDINGS",
            "1 TRIAGED",
            "1 PENDING",
            // Severity chips uppercase per design.
            "F-0001",
            "HIGH",
            "F-0002",
            "MEDIUM",
            // Compact row 1 carries title + location.
            "SQL injection in admin search",
            "src/controllers/admin_search.ts:117-119",
            // Compact row 2 detail line.
            "tp",
            "91%",
            "CWE-89",
            "semgrep",
            "untriaged",
            "codeql",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
        for y in 0..24 {
            let row = buffer_row_text(buffer, 80, y);
            assert!(
                row.chars().count() <= 80,
                "row exceeded 80 columns: {row:?}"
            );
        }
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_actionable_empty_states_at_80_columns() {
        for (view, expected) in [
            (ShellView::Findings, "Next: scan"),
            (ShellView::Runs, "Next: `scan`"),
            (ShellView::Workspace, "Next: scan <target>"),
        ] {
            let backend = TestBackend::new(80, 18);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            let is_dfd = matches!(view, ShellView::Threat(ThreatView::Dfd));
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(expected), "missing {expected}");
            // Box-drawing is reserved for the DFD diagram; every other view
            // must remain free of nested boxes (no Ink-style boxed dashboard).
            if !is_dfd {
                assert!(!rendered.contains("┌"), "{expected} drew a box");
            }
        }
    }

    #[test]
    fn renders_long_prompt_on_single_row() {
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.input = "scan ./a/very/long/path/that/should/not/wrap".to_string();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("kuzushi>"));
        assert!(!rendered.contains("prompt"));
    }

    #[test]
    fn keeps_command_log_directly_above_bottom_prompt_at_80_columns() {
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log(
            "error",
            "scanner failed while reading src/really/long/path/that/must/not_overlap.rs",
        );
        app.log(
            "result",
            "next action: inspect configuration and rerun scan with a narrower target",
        );
        app.input = "run sast:scan {\"severity\":[\"high\"],\"triage\":true}".to_string();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let prompt_row = buffer_row_text(buffer, 80, 11);
        let log_row = buffer_row_text(buffer, 80, 10);

        assert!(prompt_row.trim_start().starts_with("kuzushi>"));
        assert!(prompt_row.contains("triage"));
        assert!(!prompt_row.contains("result"));
        assert!(log_row.contains("result"));
        assert!(!log_row.contains("kuzushi>"));
        assert!(!format!("{:?}", buffer).contains("┌"));
    }

    #[test]
    fn renders_exit_commands_before_closing() {
        for command in ["/exit", "exit", "/exitj"] {
            let backend = TestBackend::new(80, 12);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);

            app.submit_line(command);
            assert!(app.should_quit, "{command} should request shell shutdown");

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let buffer = terminal.backend().buffer();
            let command_row = buffer_row_text(buffer, 80, 9);
            let exit_row = buffer_row_text(buffer, 80, 10);
            let prompt_row = buffer_row_text(buffer, 80, 11);

            assert!(
                command_row.contains(command),
                "{command} should remain visible in the transcript"
            );
            assert!(exit_row.contains("exit requested; closing shell"));
            assert!(prompt_row.trim_start().starts_with("kuzushi>"));
        }
    }

    #[test]
    fn replay_and_trace_surfaces_reuse_current_finding_aliases() {
        for view in [
            ShellView::Replay("run-1".to_string()),
            ShellView::Trace("run-1".to_string()),
        ] {
            let backend = TestBackend::new(80, 18);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            let mut finding =
                Finding::new_semgrep("demo.rule", "src/app.ts", 8, None, Severity::High, "sink");
            finding.fingerprint = "aaaa1111".to_string();
            app.findings = vec![finding];
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains("ALIASES"));
            assert!(rendered.contains("F-0001"));
            assert!(rendered.contains("aaaa1111"));
        }
    }

    #[test]
    fn renders_threat_view_navigation() {
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stride);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("STRIDE"));
        assert!(rendered.contains("Spoofing"));
    }

    #[test]
    fn renders_pending_threat_patch_card() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_pending_threat_patch(crate::app::ThreatPatch {
            goal: "regen".to_string(),
            summary: "add admin trust zone".to_string(),
            patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
            unsupported: vec!["manual review required".to_string()],
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("THREAT PATCH"));
        assert!(rendered.contains("add admin trust zone"));
        assert!(rendered.contains("1 top-level key"));
        assert!(rendered.contains("/threats apply"));
        assert!(rendered.contains("/threats reject"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_expanded_catalog_readably_on_narrow_terminal() {
        let backend = TestBackend::new(58, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(crate::commands::ShellCommand::Modules);
        app.findings = (0..82)
            .map(|index| {
                Finding::new_semgrep(
                    format!("demo.rule.{index}"),
                    "src/app.ts",
                    index + 1,
                    None,
                    Severity::Medium,
                    "demo finding",
                )
            })
            .collect();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("82 findings"));
        assert!(rendered.contains("semgrep"));
        // Category divider embeds the section blurb on the rule line — see
        // `category_divider` and `design/mockups/catalog.jsx::catHead`. Narrow
        // terminals truncate, so assert on the shortest blurb word that
        // survives an 58-col render: "OFFENSE" itself.
        assert!(rendered.contains("OFFENSE"));
        assert!(!rendered.contains("module context-lite"));
        assert!(!rendered.contains("command log"));
    }

    #[test]
    fn expanded_catalog_uses_design_sections_without_dag_column() {
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(crate::commands::ShellCommand::Modules);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("KUZUSHI · CATALOG"));
        assert!(rendered.contains("▸ NEXT"));
        assert!(rendered.contains("OFFENSE"));
        assert!(rendered.contains("sast"));
        assert!(!rendered.contains("dag"));
        assert!(!rendered.contains("DAG"));
    }

    #[test]
    fn catalog_next_hint_steers_through_context_then_findings() {
        let mut app = ShellApp::new(V2Config::default(), None);

        // Default fresh app: no context snapshot built.
        assert!(
            catalog_next_hint(&app).contains("context build"),
            "fresh app should suggest context build"
        );

        // After context exists but no findings: first-finding scan hint.
        app.context_view.exists = true;
        let hint = catalog_next_hint(&app);
        assert!(
            hint.contains("First finding") || hint.contains("scan"),
            "ctx-built no-findings should suggest scanning, got: {hint}"
        );

        // With non-critical findings: drill-in suggestion.
        let medium = Finding::new_semgrep("demo.rule", "src/a.rs", 1, None, Severity::Medium, "x");
        app.findings = vec![medium];
        let hint = catalog_next_hint(&app);
        assert!(hint.contains("findings"), "got: {hint}");
        assert!(hint.contains("triage"), "got: {hint}");

        // With a critical finding: open-by-alias suggestion.
        let critical =
            Finding::new_semgrep("demo.crit", "src/b.rs", 2, None, Severity::Critical, "y");
        app.findings.push(critical);
        let hint = catalog_next_hint(&app);
        assert!(hint.contains("open F-"), "got: {hint}");
    }

    #[test]
    fn spinner_cycles_through_six_frames_by_log_length() {
        let scan = crate::app::ScanPanelState {
            run_id: None,
            target: std::path::PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        };
        let frames: Vec<&str> = (0..12)
            .map(|tick| run_state_glyph(Some(&scan), tick))
            .collect();
        // First 6 ticks cover all 6 frames
        let unique: std::collections::BTreeSet<&&str> = frames.iter().take(6).collect();
        assert_eq!(
            unique.len(),
            6,
            "first 6 frames should be unique: {frames:?}"
        );
        // Frame at tick N == frame at tick N+6 (cycle period)
        for tick in 0..6 {
            assert_eq!(
                frames[tick],
                frames[tick + 6],
                "spinner should repeat every 6 ticks"
            );
        }
    }

    #[test]
    fn spinner_shows_static_glyph_when_scan_idle_or_done() {
        // Idle: no scan -> ●
        assert_eq!(run_state_glyph(None, 0), "●");
        assert_eq!(run_state_glyph(None, 99), "●");
        // Done: scan present, not running, no error -> ✓
        let done = crate::app::ScanPanelState {
            run_id: None,
            target: std::path::PathBuf::from("."),
            stage: String::new(),
            findings_count: 0,
            running: false,
            abort_requested: false,
            error: None,
        };
        assert_eq!(run_state_glyph(Some(&done), 4), "✓");
    }

    #[test]
    fn module_run_body_ends_with_streaming_cursor_when_scan_active() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-abc".to_string()),
            target: std::path::PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;
        let area = Rect::new(0, 0, 120, 30);
        let lines = module_run_lines(&app, area);
        let last = lines.last().expect("expected non-empty body");
        let last_text: String = last.spans.iter().map(|s| s.content.as_ref()).collect();
        // The cursor line is " " + a single styled-block " ", so two visible cells.
        assert_eq!(
            last_text, "  ",
            "expected streaming cursor line at end while scan running, got {last_text:?}"
        );
        // Sanity: confirm a styled span with primary bg exists on that line.
        let has_inverse = last
            .spans
            .iter()
            .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
        assert!(
            has_inverse,
            "streaming cursor should be a styled background cell"
        );
    }

    #[test]
    fn module_run_body_omits_streaming_cursor_when_idle() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::ModuleRun;
        let area = Rect::new(0, 0, 120, 30);
        let lines = module_run_lines(&app, area);
        // No scan → no streaming cursor expected.
        for line in &lines {
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            let has_cursor = line
                .spans
                .iter()
                .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
            assert!(
                !has_cursor || text.trim() != "",
                "unexpected streaming cursor while idle: {text:?}"
            );
        }
    }

    #[test]
    fn recent_module_activity_uses_recon_snapshot_when_present() {
        use crate::app::ReconSnapshot;
        use kuzushi_core::{ReconHost, ReconService};

        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("recon".to_string());
        app.shell_view = ShellView::Module;
        app.recon_snapshot = Some(ReconSnapshot {
            hosts: vec![ReconHost {
                id: "h1".to_string(),
                workspace_id: "ws".to_string(),
                address: "192.0.2.10".to_string(),
                hostname: Some("acme-checkout.com".to_string()),
                state: "alive".to_string(),
            }],
            services: vec![ReconService {
                id: "s1".to_string(),
                host_id: "h1".to_string(),
                port: 443,
                proto: "tcp".to_string(),
                name: Some("https".to_string()),
                banner: Some("nginx/1.24 · TLS1.3".to_string()),
                state: "open".to_string(),
            }],
            notes: Vec::new(),
            last_tool: Some("recon:nmap".to_string()),
            last_target: Some("acme-checkout.com".to_string()),
        });

        let area = Rect::new(0, 0, 120, 40);
        let lines = module_lines(&app, area);
        let rendered: String = lines
            .iter()
            .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
            .collect::<Vec<_>>()
            .join("");

        assert!(
            rendered.contains("acme-checkout.com"),
            "expected snapshot host in output, got:\n{rendered}"
        );
        assert!(
            rendered.contains("443"),
            "expected snapshot port 443 in output, got:\n{rendered}"
        );
        assert!(
            rendered.contains("nginx/1.24"),
            "expected snapshot banner in output, got:\n{rendered}"
        );
        assert!(
            rendered.contains("RECENT RECON ACTIVITY"),
            "expected RECENT RECON ACTIVITY header, got:\n{rendered}"
        );
    }

    #[test]
    fn recent_module_activity_falls_back_to_log_when_no_snapshot() {
        // No snapshot is populated → renderer must keep falling back to the
        // legacy `app.log` grep, which is the pre-snapshot behaviour.
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("recon".to_string());
        app.shell_view = ShellView::Module;
        // Inject a recon-shaped log line that would be picked up by
        // `recent_module_log` filter (prefix == "result", body contains "recon").
        app.log(
            "result",
            "recon:nmap discovered 1 host and 2 open services for 192.0.2.10",
        );

        let area = Rect::new(0, 0, 120, 40);
        let lines = module_lines(&app, area);
        let rendered: String = lines
            .iter()
            .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
            .collect::<Vec<_>>()
            .join("");

        assert!(
            rendered.contains("recon:nmap discovered 1 host"),
            "expected fallback log-grep line in output, got:\n{rendered}"
        );
        assert!(
            rendered.contains("RECENT RECON ACTIVITY"),
            "expected RECENT RECON ACTIVITY header, got:\n{rendered}"
        );
    }

    #[test]
    fn sast_progress_bars_use_scan_progress_per_task_when_present() {
        use kuzushi_core::ScanProgress;
        use std::collections::BTreeMap;

        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("sast".to_string());
        app.shell_view = ShellView::ModuleRun;
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-real-progress".to_string()),
            target: std::path::PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });

        let mut per_task = BTreeMap::new();
        per_task.insert("agentic-sast".to_string(), (87usize, 120usize));
        per_task.insert("semgrep".to_string(), (612usize, 612usize));
        app.scan_progress = Some(ScanProgress {
            total: 732,
            done: 699,
            current_tool: Some("semgrep".to_string()),
            current_target: Some("./demo".to_string()),
            per_task,
        });

        let area = Rect::new(0, 0, 120, 40);
        let lines = module_run_lines(&app, area);
        let rendered: String = lines
            .iter()
            .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
            .collect::<Vec<_>>()
            .join("");

        assert!(
            rendered.contains("612/612"),
            "expected real semgrep done count, got:\n{rendered}"
        );
        assert!(
            rendered.contains("87/120"),
            "expected real agentic-sast progress count, got:\n{rendered}"
        );
        assert!(
            rendered.contains("semgrep"),
            "expected semgrep label in progress bar, got:\n{rendered}"
        );
        assert!(
            rendered.contains("agentic-sast"),
            "expected agentic-sast label in progress bar, got:\n{rendered}"
        );
    }

    #[test]
    fn stories_from_doc_sorts_threats_by_impact_severity() {
        let doc = serde_json::json!({
            "threats": [
                {"id": "T-001", "title": "low risk",  "impact": "low",      "category": "spoofing",  "attackVector": "vec1"},
                {"id": "T-002", "title": "critical bug", "impact": "critical","category": "tampering","attackVector": "vec2",
                 "affectedFiles": [{"filePath": "src/api.rs", "startLine": 42}]},
                {"id": "T-003", "title": "high issue", "impact": "high",     "category": "elevation_of_privilege"}
            ]
        });
        let stories = stories_from_doc(&doc).expect("non-empty stories");
        assert_eq!(stories.len(), 3);
        assert_eq!(stories[0].0, "T-002");
        assert_eq!(stories[0].1, Severity::Critical);
        assert_eq!(stories[0].4, "src/api.rs:42");
        assert_eq!(stories[1].0, "T-003");
        assert_eq!(stories[1].1, Severity::High);
        assert_eq!(stories[2].0, "T-001");
    }

    #[test]
    fn scope_buckets_from_doc_groups_by_impact() {
        let doc = serde_json::json!({
            "threats": [
                {"title": "a", "impact": "critical"},
                {"title": "b", "impact": "high"},
                {"title": "c", "impact": "high"},
                {"title": "d", "impact": "medium"}
            ]
        });
        let buckets = scope_buckets_from_doc(&doc).expect("non-empty");
        assert_eq!(buckets[0].0, Severity::Critical);
        assert_eq!(buckets[0].2.len(), 1);
        assert_eq!(buckets[1].0, Severity::High);
        assert_eq!(buckets[1].2.len(), 2);
        assert_eq!(buckets[2].0, Severity::Medium);
        assert_eq!(buckets[2].2.len(), 1);
        assert_eq!(buckets[3].0, Severity::Low);
        assert!(buckets[3].2.is_empty());
    }

    #[test]
    fn threats_stories_view_renders_attacker_story_cards() {
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stories);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("ATTACKER STORIES"));
        assert!(rendered.contains("T-001"));
        assert!(rendered.contains("CRITICAL"));
        assert!(rendered.contains("attack"));
        assert!(rendered.contains("loc"));
        // Old placeholder gone
        assert!(!rendered.contains("malicious input reaches a sink"));
    }

    #[test]
    fn threats_scope_view_renders_criticality_buckets() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Scope);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("SCOPE · 11 ISSUES"),
            "expected SCOPE · 11 ISSUES in: {rendered}"
        );
        assert!(rendered.contains("CRITICAL · 2"));
        assert!(rendered.contains("HIGH · 3"));
        assert!(rendered.contains("OUT OF SCOPE"));
        // Old placeholders gone
        assert!(!rendered.contains("auth, request parsing"));
    }

    #[test]
    fn dfd_canonical_lines_render_design_diagram() {
        let lines = dfd_canonical_lines();
        assert_eq!(lines.len(), 10, "expected 10 rows in canonical DFD");
        let texts: Vec<String> = lines
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(texts[1].contains("user"));
        assert!(texts[1].contains("api edge"));
        assert!(texts[1].contains("postgres"));
        assert!(texts[4].contains("jwt"));
        assert!(texts[4].contains("plaintext PII"));
        assert!(texts[7].contains("worker pool"));
        assert!(texts[7].contains("s3 (us-east)"));
        // top + bottom borders are pure box-drawing
        assert!(texts[0].contains("┌────"));
        assert!(texts[3].contains("└────"));
    }

    #[test]
    fn dfd_nodes_from_doc_returns_id_type_zone_triples() {
        let doc = serde_json::json!({
            "dfd": {
                "nodes": [
                    {"id": "actor-user", "type": "external-entity", "name": "User",
                     "description": "End user", "trustZone": "external"},
                    {"id": "web", "type": "process", "name": "Web app",
                     "description": "Server", "trustZone": "internal"}
                ]
            }
        });
        let nodes = dfd_nodes_from_doc(&doc).expect("expected non-empty nodes");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].0, "actor-user");
        assert_eq!(nodes[0].1, "external-entity");
        assert_eq!(nodes[0].2, "external");
        assert_eq!(nodes[1].0, "web");
        assert_eq!(nodes[1].2, "internal");
    }

    #[test]
    fn dfd_nodes_from_doc_returns_none_when_missing() {
        assert!(dfd_nodes_from_doc(&serde_json::json!({})).is_none());
        assert!(dfd_nodes_from_doc(&serde_json::json!({"dfd": {}})).is_none());
        assert!(dfd_nodes_from_doc(&serde_json::json!({"dfd": {"nodes": []}})).is_none());
    }

    #[test]
    fn threats_dfd_view_renders_canonical_diagram_header() {
        let backend = TestBackend::new(120, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Dfd);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("DFD · ACME-CHECKOUT"),
            "expected DFD section header in: {rendered}"
        );
        assert!(rendered.contains("user"));
        assert!(rendered.contains("api edge"));
        assert!(rendered.contains("postgres"));
        assert!(rendered.contains("worker pool"));
        // Old placeholder content must be gone.
        assert!(!rendered.contains("browser, API clients, package registries"));
        assert!(!rendered.contains("source tree, handlers, jobs, CLIs"));
    }

    #[test]
    fn stride_rollup_from_doc_parses_real_threats() {
        let doc = serde_json::json!({
            "threats": [
                {"id": "T-001", "category": "spoofing",          "title": "spoofed login",    "impact": "high"},
                {"id": "T-002", "category": "spoofing",          "title": "stolen token",     "impact": "medium"},
                {"id": "T-003", "category": "tampering",         "title": "config tamper",    "impact": "critical"},
                {"id": "T-004", "category": "information-disclosure", "title": "log leak",    "impact": "low"},
            ]
        });
        let rollup = stride_rollup_from_doc(&doc).expect("expected rollup from non-empty threats");
        assert_eq!(rollup.len(), 6);

        let total: usize = rollup.iter().map(|r| r.3).sum();
        assert_eq!(total, 4);

        // Spoofing: 2 threats, max impact = high
        let spoof = &rollup[0];
        assert_eq!(spoof.0, "S");
        assert_eq!(spoof.2, "Spoofing");
        assert_eq!(spoof.3, 2);
        assert_eq!(spoof.1, Severity::High);
        assert!(spoof.4.contains("spoofed login"));
        assert!(spoof.4.contains("stolen token"));

        // Tampering: 1 threat, impact = critical
        let tamper = &rollup[1];
        assert_eq!(tamper.3, 1);
        assert_eq!(tamper.1, Severity::Critical);
        assert_eq!(tamper.4, "config tamper");

        // Repudiation: 0 threats, default Low severity, empty description
        let repud = &rollup[2];
        assert_eq!(repud.3, 0);
        assert_eq!(repud.1, Severity::Low);
        assert!(repud.4.is_empty());

        // Info-disclosure: 1 threat, impact = low
        let info = &rollup[3];
        assert_eq!(info.3, 1);
        assert_eq!(info.1, Severity::Low);
        assert_eq!(info.4, "log leak");
    }

    #[test]
    fn stride_rollup_from_doc_returns_none_on_empty_or_missing_threats() {
        assert!(stride_rollup_from_doc(&serde_json::json!({})).is_none());
        assert!(stride_rollup_from_doc(&serde_json::json!({"threats": []})).is_none());
        assert!(stride_rollup_from_doc(&serde_json::json!({"threats": null})).is_none());
    }

    #[test]
    fn stride_rollup_from_doc_normalizes_underscored_categories() {
        let doc = serde_json::json!({
            "threats": [
                {"category": "denial_of_service",        "title": "ddos",  "impact": "medium"},
                {"category": "elevation_of_privilege",   "title": "sudo bypass", "impact": "critical"},
            ]
        });
        let rollup = stride_rollup_from_doc(&doc).expect("rollup should accept underscored");
        let dos = &rollup[4];
        assert_eq!(dos.0, "D");
        assert_eq!(dos.3, 1);
        let elev = &rollup[5];
        assert_eq!(elev.0, "E");
        assert_eq!(elev.3, 1);
        assert_eq!(elev.1, Severity::Critical);
    }

    #[test]
    fn threats_summary_view_combines_stride_rollup_and_observations() {
        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Summary);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("THREAT MODEL · 8 ISSUES"),
            "expected design summary header in: {rendered}"
        );
        assert!(rendered.contains("Spoofing"));
        assert!(rendered.contains("admin.acme-checkout.com"));
        assert!(rendered.contains("threat-model.json"));
    }

    #[test]
    fn threats_stride_view_renders_design_rollup() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stride);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("STRIDE ROLLUP"),
            "expected STRIDE ROLLUP header in: {rendered}"
        );
        assert!(rendered.contains("Spoofing"));
        assert!(rendered.contains("Tampering"));
        assert!(rendered.contains("Repudiation"));
        assert!(rendered.contains("Info-disclosure"));
        assert!(rendered.contains("DoS"));
        assert!(rendered.contains("Elev-of-priv"));
        // Old hardcoded content must be gone.
        assert!(!rendered.contains("entrypoints"));
        assert!(!rendered.contains("scanners"));
    }

    #[test]
    fn focused_recon_module_renders_recent_activity_section() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log.clear();
        app.log(
            "recon:nmap",
            "discovered 5 hosts and 18 services for acme-checkout.com",
        );
        app.log("recon:subdomain", "discovered 7 subdomains");
        app.log("recon", "persisted 3 findings");
        app.handle_command(crate::commands::ShellCommand::Use("recon".to_string()));

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("RECENT RECON ACTIVITY"),
            "expected design section header for recon: {rendered}"
        );
        assert!(rendered.contains("discovered 5 hosts"));
        assert!(rendered.contains("discovered 7 subdomains"));
    }

    #[test]
    fn focused_carlini_module_renders_recent_threat_hunt_activity() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log.clear();
        app.log("carlini-threat-hunt", "actor 1/4 dispatched");
        app.log("carlini-threat-hunt", "actor 2/4 found path-traversal sink");
        app.handle_command(crate::commands::ShellCommand::Use(
            "carlini-threat-hunt".to_string(),
        ));

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("RECENT THREAT-HUNT ACTIVITY"),
            "expected design section header for carlini: {rendered}"
        );
        assert!(rendered.contains("actor 1/4 dispatched"));
    }

    #[test]
    fn module_run_transcript_uses_growing_console_glyphs() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log.clear();
        app.log(">", "/scan");
        app.log("scan", "starting ./demo");
        app.log("finding", "abc123 high dangerous sink");
        app.log("error", "scanner failed");
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-123456".to_string()),
            target: std::path::PathBuf::from("./demo"),
            stage: "agentic-sast tracing".to_string(),
            findings_count: 1,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("SCAN PROGRESS"));
        // Spinner cycles through SPINNER_FRAMES based on `app.spinner_phase`; any frame is valid.
        assert!(
            SPINNER_FRAMES.iter().any(|frame| rendered.contains(frame)),
            "expected one of the braille spinner frames in: {rendered}"
        );
        assert!(rendered.contains("● /scan"));
        assert!(rendered.contains("⏵ scan starting ./demo"));
        assert!(rendered.contains("▸ finding abc123 high dangerous sink"));
        assert!(rendered.contains("✗ error scanner failed"));
    }

    #[test]
    fn direct_tool_run_header_does_not_show_pending_scan_run() {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("context".to_string());
        app.shell_view = ShellView::ModuleRun;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("tool run"));
        assert!(!rendered.contains("run pending"));
    }

    #[test]
    fn renders_options_table_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            serde_json::json!(true),
        );
        app.shell_view = ShellView::Options(crate::app::OptionsView {
            tool_name: "sast:scan".to_string(),
            filter: crate::app::OptionsFilter::Standard,
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("OPTIONS"));
        assert!(rendered.contains("sast:scan"));
        assert!(rendered.contains("tasks"));
        assert!(rendered.contains("disabledTasks"));
        assert!(rendered.contains("triage"));
        assert!(rendered.contains("true"));
        assert!(rendered.contains("set <key> <value>"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_sast_task_picker_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::SastTasks;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("SAST TASKS"));
        assert!(rendered.contains("semgrep"));
        assert!(rendered.contains("codeql"));
        assert!(rendered.contains("auto + denylist"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_kb_attachments_readably_at_80_columns() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.kb_view.module_id = "x-ray".to_string();
        app.kb_view.artifacts = vec![kuzushi_core::KnownArtifact {
            module_id: "x-ray".to_string(),
            path: "x-ray/x-ray.md".to_string(),
            description: "x-ray report".to_string(),
            exists: true,
        }];
        app.kb_view.attachments = vec![kuzushi_core::AttachmentRecord {
            id: "A-123456789abc".to_string(),
            module_id: "x-ray".to_string(),
            kind: kuzushi_core::AttachmentKind::Url,
            source: "https://example.test/design".to_string(),
            title: "example.test".to_string(),
            metadata_only: true,
            content_hash: None,
            byte_count: None,
            status: "metadata-only; URL was not fetched".to_string(),
            updated_at_unix: 1,
        }];
        app.shell_view = ShellView::KnowledgeBase;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("KB ATTACHMENTS"));
        assert!(rendered.contains("x-ray/x-ray.md"));
        assert!(rendered.contains("A-123456789abc"));
        assert!(rendered.contains("metadata-only"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_context_status_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.context_view = crate::app::ContextSnapshotView {
            snapshot_path: Some(std::path::PathBuf::from(".kuzushi/context-snapshot.json")),
            exists: true,
            status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(2),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
        };
        app.shell_view = ShellView::Context;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("CONTEXT"));
        assert!(rendered.contains("context-snapshot.json"));
        assert!(rendered.contains("Rust"));
        assert!(rendered.contains("context regen repo"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_workspace_status_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.workspace_view = crate::app::WorkspaceView {
            root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
            findings_db: Some(std::path::PathBuf::from(
                "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
            )),
            findings_count: Some(2),
            last_export: Some(std::path::PathBuf::from("/tmp/findings.json")),
            status: "workspace ready; 2 finding(s). Next: workspace export findings <path>.json"
                .to_string(),
        };
        app.shell_view = ShellView::Workspace;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("WORKSPACE"));
        assert!(rendered.contains("findings.sqlite3"));
        assert!(rendered.contains("findings.json"));
        assert!(rendered.contains("workspace export"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn workspace_view_renders_findings_rollup_bar_when_findings_exist() {
        // Mockup parity: `design/mockups/workspace.jsx::rollupBar`. With
        // persisted findings, the workspace view shows a 28-cell severity
        // rollup bar per category so the operator sees the distribution
        // shape at a glance.
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.workspace_view = crate::app::WorkspaceView {
            root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: None,
            findings_db: None,
            findings_count: Some(38),
            last_export: None,
            status: "workspace ready".to_string(),
        };
        app.findings = (0..38)
            .map(|index| {
                let sev = match index % 4 {
                    0 => Severity::Critical,
                    1 => Severity::High,
                    2 => Severity::Medium,
                    _ => Severity::Low,
                };
                Finding::new_semgrep(
                    format!("rule.{index}"),
                    "src/x.rs",
                    index + 1,
                    None,
                    sev,
                    "demo",
                )
            })
            .collect();
        app.shell_view = ShellView::Workspace;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("FINDINGS ROLLUP"),
            "missing rollup divider: {rendered}"
        );
        assert!(rendered.contains("CRITICAL"));
        assert!(rendered.contains("HIGH"));
        assert!(rendered.contains("MEDIUM"));
        assert!(rendered.contains("LOW"));
        assert!(rendered.contains("█"));
        assert!(rendered.contains("░"));
        assert!(rendered.contains("/38"));
    }

    #[test]
    fn workspace_view_skips_rollup_when_no_findings() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Workspace;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        // No findings → no FINDINGS ROLLUP section (no empty bars to show).
        assert!(!rendered.contains("FINDINGS ROLLUP"));
    }

    #[test]
    fn plain_options_table_has_no_ansi_or_box_drawing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            serde_json::json!(true),
        );
        app.shell_view = ShellView::Options(crate::app::OptionsView {
            tool_name: "sast:scan".to_string(),
            filter: crate::app::OptionsFilter::Standard,
        });

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("OPTIONS"));
        assert!(rendered.contains("sast:scan"));
        assert!(rendered.contains("triage"));
        assert!(rendered.contains("true"));
        assert!(rendered.contains("Next: set <key> <value>"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn plain_kb_list_has_no_ansi_or_box_drawing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.kb_view.module_id = "x-ray".to_string();
        app.kb_view.artifacts = vec![kuzushi_core::KnownArtifact {
            module_id: "x-ray".to_string(),
            path: "x-ray/x-ray.md".to_string(),
            description: "x-ray report".to_string(),
            exists: true,
        }];
        app.kb_view.attachments = vec![kuzushi_core::AttachmentRecord {
            id: "A-123456789abc".to_string(),
            module_id: "x-ray".to_string(),
            kind: kuzushi_core::AttachmentKind::Url,
            source: "https://example.test/design".to_string(),
            title: "example.test".to_string(),
            metadata_only: true,
            content_hash: None,
            byte_count: None,
            status: "metadata-only; URL was not fetched".to_string(),
            updated_at_unix: 1,
        }];
        app.shell_view = ShellView::KnowledgeBase;

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("KB ATTACHMENTS"));
        assert!(rendered.contains("x-ray/x-ray.md"));
        assert!(rendered.contains("A-123456789abc"));
        assert!(rendered.contains("metadata-only"));
        assert!(rendered.contains("Next: kb [module]"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn plain_context_status_has_no_ansi_or_box_drawing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.context_view = crate::app::ContextSnapshotView {
            snapshot_path: Some(std::path::PathBuf::from(".kuzushi/context-snapshot.json")),
            exists: true,
            status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(2),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
        };
        app.shell_view = ShellView::Context;

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("CONTEXT"));
        assert!(rendered.contains("context-snapshot.json"));
        assert!(rendered.contains("Rust"));
        assert!(rendered.contains("context regen repo"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn plain_context_guidance_wraps_without_truncating_next_steps() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Context;

        let rendered = render_plain_app(&app, 56);

        assert!(rendered.contains("No context snapshot exists yet."));
        assert!(rendered.contains(".kuzushi/context-snapshot.json"));
        assert!(rendered.contains("context build"));
        assert!(rendered.contains("context regen repo"));
        assert!(!rendered.contains("context-s..."));
        assert_strict_plain_width(&rendered, 56);
    }

    #[test]
    fn plain_workspace_guidance_wraps_without_truncating_export_command() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.workspace_view = crate::app::WorkspaceView {
            root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
            findings_db: Some(std::path::PathBuf::from(
                "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
            )),
            findings_count: Some(2),
            last_export: None,
            status: "workspace ready; 2 finding(s). Next: workspace export findings <path>.json"
                .to_string(),
        };
        app.shell_view = ShellView::Workspace;

        let rendered = render_plain_app(&app, 52);

        assert!(rendered.contains("workspace ready; 2 finding(s)."));
        assert!(rendered.contains("workspace export findings <path>.json"));
        assert!(!rendered.contains("workspace export findings..."));
        assert_strict_plain_width(&rendered, 52);
    }

    #[test]
    fn plain_help_guidance_wraps_without_truncating_command_shapes() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        let rendered = render_plain_app(&app, 64);

        assert!(rendered.contains("HELP"));
        assert!(rendered.contains("ask <question>"));
        assert!(rendered.contains("enter agent mode"));
        assert!(rendered.contains("workspace export findings <path>"));
        assert!(rendered.contains("/workspace export findings <path>"));
        assert!(!rendered.contains("workspace export findings <..."));
        assert_strict_plain_width(&rendered, 64);
    }

    #[test]
    fn renders_config_onboarding_without_silent_model_selection() {
        let backend = TestBackend::new(100, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.config.model = None;
        app.session_thinking_level = None;
        app.selected_model_index = 2;
        app.shell_view = ShellView::Config;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("provider"));
        assert!(rendered.contains("unconfigured"));
        assert!(rendered.contains("reasoning"));
        assert!(rendered.contains("default"));
        assert!(rendered.contains("onboarding"));
        assert!(rendered.contains("Up/Down"));
        assert!(rendered.contains(">"));
        assert!(rendered.contains("openai-codex:gpt-5.5"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_help_grouped_by_operator_workflow() {
        let backend = TestBackend::new(110, 130);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        for heading in [
            "NAVIGATION",
            "RUN / SCAN",
            "OPTIONS / TASKS",
            "CONTEXT / KB",
            "FINDINGS / EVIDENCE",
            "AUTH / CONFIG / MODEL",
            "SESSION",
        ] {
            assert!(rendered.contains(heading), "missing help group {heading}");
        }
        assert!(rendered.contains("options [tool]"));
        assert!(rendered.contains("task toggle"));
        assert!(rendered.contains("kb [module]"));
        assert!(rendered.contains("auth login"));
        assert!(rendered.contains("? opens help"));
        assert!(rendered.contains("?text"));
        assert!(rendered.contains("/ask <question>"));
        assert!(rendered.contains("ask <question>"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_help_aliases_and_examples_from_command_specs() {
        let backend = TestBackend::new(120, 130);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        for example in shell_help_examples() {
            assert!(
                rendered.contains(example),
                "missing featured help example {example}"
            );
        }

        for (category, alias) in [
            (ShellCommandCategory::Navigation, "/h"),
            (ShellCommandCategory::RunScan, "run ."),
            (ShellCommandCategory::OptionsTasks, "task deny <id>"),
            (ShellCommandCategory::ContextKb, "attachments"),
            (ShellCommandCategory::FindingsEvidence, "open F-0001"),
            (ShellCommandCategory::AuthConfigModel, "model 1"),
            (ShellCommandCategory::Session, "q"),
        ] {
            assert!(
                shell_command_specs()
                    .iter()
                    .any(|spec| spec.category == category && spec.aliases.contains(&alias)),
                "sample alias {alias:?} is not registered for {category:?}"
            );
            assert!(
                rendered.contains(alias),
                "missing help alias sample {alias:?} for {category:?}"
            );
        }

        // Per `design/mockups/help.jsx`, sections embed their blurb on the
        // category divider rule line — no separate `aliases / examples` table
        // header.  The featured-example + per-category alias assertions
        // above already prove the alias/example text reaches the buffer.
        assert!(rendered.contains("browse modules and tools"));
        assert!(!rendered.contains("TypeScript"));
        assert!(!rendered.contains("Ink"));
    }

    #[test]
    fn plain_help_aliases_and_examples_are_width_safe() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("HELP"));
        assert!(rendered.contains("browse modules and tools"));
        for example in shell_help_examples() {
            assert!(
                rendered.contains(example),
                "missing plain help example {example}"
            );
        }
        for alias in [
            "/h",
            "run .",
            "task deny <id>",
            "attachments",
            "open F-0001",
            "model 1",
            "q",
        ] {
            assert!(rendered.contains(alias), "missing plain help alias {alias}");
        }
        assert!(!rendered.contains("TypeScript"));
        assert!(!rendered.contains("Ink"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn viewport_help_remains_navigable_at_24_rows() {
        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let first_page = format!("{:?}", terminal.backend().buffer());
        assert!(first_page.contains("HELP"));
        assert!(first_page.contains("NAVIGATION"));

        app.help_scroll = usize::MAX;
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let last_page = format!("{:?}", terminal.backend().buffer());
        assert!(last_page.contains("SESSION"));
        assert!(last_page.contains("PgUp/PgDn scroll"), "{last_page}");
        assert!(!last_page.contains("┌"));
    }

    #[test]
    fn viewport_tools_remain_navigable_at_24_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let last_tool = app.registry.tools().last().unwrap().name.clone();
        app.shell_view = ShellView::Tools;
        app.tools_scroll = usize::MAX;

        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(&last_tool),
            "missing last tool {last_tool}"
        );
        assert!(rendered.contains("PgUp/PgDn scroll"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn viewport_expanded_modules_remain_navigable_at_24_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let last_defense_module = app
            .registry
            .modules()
            .filter(|module| module_category(module.metadata().kind).0 == "DEFENSE")
            .last()
            .unwrap()
            .metadata()
            .id
            .clone();
        app.shell_view = ShellView::Catalog;
        app.catalog_expanded = true;
        app.modules_scroll = usize::MAX;

        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(&last_defense_module),
            "missing last module {last_defense_module}"
        );
        assert!(rendered.contains("PgUp/PgDn scroll"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn viewport_findings_keeps_cursor_visible_at_24_rows() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.findings_cursor = 29;
        app.findings = (0..30)
            .map(|index| {
                let mut finding = Finding::new_semgrep(
                    format!("demo.rule.{index:04}"),
                    "src/app.rs",
                    index + 1,
                    None,
                    Severity::High,
                    format!("title-{index:02}\nEvidence: proof-{index:02}"),
                );
                finding.fingerprint = format!("fp-{index:04}");
                finding
            })
            .collect();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("F-0030"));
        assert!(rendered.contains("title-29"));
        assert!(!rendered.contains("F-0001"));
        assert!(rendered.contains("j/k/g/G move"));
        assert!(rendered.contains("PgUp/PgDn page"));
        assert!(rendered.contains("Enter open"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn keybind_footer_advertises_findings_navigation_keys_at_80_columns() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.findings = vec![Finding::new_semgrep(
            "demo.rule",
            "src/app.rs",
            1,
            None,
            Severity::High,
            "title\nEvidence: proof",
        )];

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("j/k/g/G move"));
        assert!(rendered.contains("PgUp/PgDn page"));
        assert!(rendered.contains("Enter open"));
        assert!(!rendered.contains("[open <id>]"));
    }

    #[test]
    fn keybind_footer_advertises_module_run_actor_and_pause_resume_keys() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let cancel = ScanCancellation::default();
        app.set_scan_cancel_for_test(cancel.clone());
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: std::path::PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let running = format!("{:?}", terminal.backend().buffer());
        assert!(running.contains("1..4 actor"));
        assert!(running.contains("p pause"));
        assert!(!running.contains("[actor 1]"));

        cancel.pause();
        if let Some(scan) = &mut app.scan {
            scan.stage = "paused".to_string();
        }
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let paused = format!("{:?}", terminal.backend().buffer());
        assert!(paused.contains("1..4 actor"));
        assert!(paused.contains("r resume"));
        // The unbracketed pause hint is gone too (sanity: keybind list flips
        // pause→resume on pause).
        assert!(!paused.contains("p pause"));
    }

    #[test]
    fn renders_agent_chat_mode_while_question_is_active() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-4.1".to_string()),
                ..V2Config::default()
            },
            None,
        );
        app.agent_chat = Some(crate::app::AgentChatView {
            question: "What should I run first?".to_string(),
            answer: None,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::AgentChat;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("AGENT"));
        assert!(rendered.contains("running"));
        assert!(rendered.contains("mode:agent"));
        assert!(rendered.contains("agent: active"));
        assert!(rendered.contains("kuzushi/agent>"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_honest_abort_requested_states() {
        let backend = TestBackend::new(96, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-4.1".to_string()),
                ..V2Config::default()
            },
            None,
        );
        app.shell_view = ShellView::AgentChat;
        app.agent_chat = Some(crate::app::AgentChatView {
            question: "What changed?".to_string(),
            answer: None,
            running: true,
            abort_requested: true,
            error: None,
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let agent_rendered = format!("{:?}", terminal.backend().buffer());
        assert!(agent_rendered.contains("abort requested"));
        assert!(agent_rendered.contains("Process kill is not confirmed"));
        assert!(!agent_rendered.contains("killed"));

        let backend = TestBackend::new(96, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        app.shell_view = ShellView::ModuleRun;
        app.agent_chat = None;
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: std::path::PathBuf::from("."),
            stage: "abort requested".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: true,
            error: None,
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let scan_rendered = format!("{:?}", terminal.backend().buffer());
        assert!(scan_rendered.contains("abort requested"));
        assert!(scan_rendered.contains("waiting for subprocess"));
        assert!(!scan_rendered.contains("killed"));
    }

    #[test]
    fn renders_shell_module_plan_and_run_routing_modes() {
        let cases = [
            {
                let app = ShellApp::new(V2Config::default(), None);
                (app, "mode:shell", "kuzushi>")
            },
            {
                let mut app = ShellApp::new(V2Config::default(), None);
                app.focused_module = Some("sast".to_string());
                app.shell_view = ShellView::Module;
                (app, "mode:module", "kuzushi/sast>")
            },
            {
                let mut app = ShellApp::new(V2Config::default(), None);
                app.set_pending_plan(crate::app::PlanProposal {
                    goal: "tighten SAST options".to_string(),
                    summary: "set scanner controls".to_string(),
                    changes: Vec::new(),
                    unsupported: Vec::new(),
                });
                (app, "mode:plan", "kuzushi/plan>")
            },
            {
                let mut app = ShellApp::new(V2Config::default(), None);
                app.scan = Some(crate::app::ScanPanelState {
                    run_id: Some("run-1".to_string()),
                    target: std::path::PathBuf::from("."),
                    stage: "running semgrep".to_string(),
                    findings_count: 0,
                    running: true,
                    abort_requested: false,
                    error: None,
                });
                app.shell_view = ShellView::ModuleRun;
                (app, "mode:run", "kuzushi/run>")
            },
        ];

        for (app, mode, prompt) in cases {
            let backend = TestBackend::new(96, 24);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(mode), "missing {mode} in {rendered}");
            assert!(rendered.contains(prompt), "missing {prompt} in {rendered}");
            assert!(!rendered.contains("┌"));
        }
    }

    #[test]
    fn renders_all_ink_parity_shell_surfaces() {
        let cases = vec![
            (ShellView::Catalog, "target:none"),
            (ShellView::Module, "semgrep"),
            (ShellView::ModuleRun, "TRANSCRIPT"),
            (ShellView::Findings, "filters"),
            (ShellView::Tune, "TUNE"),
            (ShellView::Threat(ThreatView::Dfd), "DFD"),
            (ShellView::Threat(ThreatView::Stories), "STORIES"),
            (ShellView::ThreatEditor, "THREAT MODEL EDIT"),
            (ShellView::PromptsEditor, "PROMPTS"),
            (ShellView::ActorDetail(1), "ACTOR 1"),
            (ShellView::Runs, "RUNS"),
            (ShellView::Replay("run-1".to_string()), "REPLAY"),
            (ShellView::Trace("run-1".to_string()), "TRACE"),
            (ShellView::Help, "HELP"),
            (ShellView::Config, "CONFIG"),
            (ShellView::Tools, "TOOLS"),
            (
                ShellView::Options(crate::app::OptionsView {
                    tool_name: "sast:scan".to_string(),
                    filter: crate::app::OptionsFilter::Standard,
                }),
                "OPTIONS",
            ),
            (ShellView::SastTasks, "SAST TASKS"),
            (ShellView::Context, "CONTEXT"),
            (ShellView::Workspace, "WORKSPACE"),
            (ShellView::KnowledgeBase, "KB ATTACHMENTS"),
            (ShellView::AgentChat, "AGENT"),
            (ShellView::History, "COMMAND HISTORY"),
            (ShellView::Story, "SESSION STORY"),
        ];

        for (view, expected) in cases {
            let backend = TestBackend::new(110, 26);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            app.focused_module = Some("semgrep".to_string());
            let is_dfd = matches!(view, ShellView::Threat(ThreatView::Dfd));
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(expected), "missing {expected}");
            // DFD diagram intentionally uses box-drawing; suppress the
            // no-Ink-dashboard guard for that one view.
            if !is_dfd {
                assert!(!rendered.contains("┌"), "{expected} drew a box");
            }
        }
    }

    fn buffer_row_text(buffer: &Buffer, width: u16, y: u16) -> String {
        let mut text = String::new();
        for x in 0..width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text
    }

    fn assert_strict_plain_80(rendered: &str) {
        assert_strict_plain_width(rendered, 80);
    }

    fn assert_strict_plain_width(rendered: &str, width: usize) {
        assert!(
            !rendered.contains('\u{1b}'),
            "plain output contained ANSI escape: {rendered:?}"
        );
        assert!(
            !rendered
                .chars()
                .any(|ch| ('\u{2500}'..='\u{257f}').contains(&ch)),
            "plain output contained box drawing: {rendered:?}"
        );
        for line in rendered.lines() {
            assert!(
                line.chars().count() <= width,
                "plain line exceeded {width} columns: {line:?}"
            );
        }
    }

    #[test]
    fn keybindings_overflow_points_at_help() {
        // P3-6: at narrow terminal widths the keybind footer used to drop
        // remaining keys under a silent `+more` token. Operators had no way
        // to discover the hidden bindings. Now the overflow chip tells
        // them where to look.
        let backend = TestBackend::new(60, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ShellApp::new(V2Config::default(), None);
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(
            rendered.contains("help more"),
            "narrow keybind footer must point at help: {rendered}"
        );
        assert!(
            !rendered.contains("+more"),
            "silent +more chip must be replaced"
        );
    }

    #[test]
    fn header_hides_cost_at_zero_and_compacts_at_higher_amounts() {
        // P4-7: at session_cost_usd == 0 the header used to render
        // `cost $0.0000` (12 chars) which pushed `model unconfigured` off
        // the right edge of 120-column terminals. Verify it's hidden until
        // a tool charges, and that the format compacts above $0.01.
        assert_eq!(format_session_cost(0.0042), "$0.0042");
        assert_eq!(format_session_cost(0.42), "$0.42");
        assert_eq!(format_session_cost(12.345), "$12.35");
        assert_eq!(format_session_cost(245.6), "$246");

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.session_cost_usd = 0.0;
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(
            !rendered.contains("cost $0.0000"),
            "header still rendered zero-cost noise: {rendered}"
        );

        // Once a real cost is reported we expect the cost segment back.
        app.session_cost_usd = 0.42;
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("cost $0.42"));
    }

    #[test]
    fn module_run_error_wraps_on_word_boundaries() {
        // P4-4: previously the SCAN PROGRESS panel rendered the scan error
        // as a single line that was truncated mid-word, hiding the
        // actionable install command. Verify the renderer now uses
        // wrap_text so the next-step suggestion survives the wrap.
        use std::path::PathBuf;
        let backend = TestBackend::new(72, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::ModuleRun;
        app.scan = Some(ScanPanelState {
            run_id: Some("abc1234".to_string()),
            target: PathBuf::from("./repo"),
            stage: "failed".to_string(),
            findings_count: 0,
            running: false,
            abort_requested: false,
            error: Some(
                "semgrep: could not find scanner binary \"semgrep\". Install Semgrep \
                 (for example `pipx install semgrep` or `brew install semgrep`)."
                    .to_string(),
            ),
        });
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("pipx install semgrep"));
        assert!(rendered.contains("brew install semgrep"));
    }

    #[test]
    fn prompt_segments_highlight_follows_app_cursor() {
        // Cursor at the END of the input — the cursor cell is the trailing
        // glyph, before_cursor contains the whole input.
        let segments = prompt_segments("kuzushi> ", "abcdef", 6, 40, " ");
        assert_eq!(segments.before_cursor, "abcdef");
        assert_eq!(segments.cursor_text, " ");
        assert_eq!(segments.after_cursor, "");

        // Cursor in the middle — the cursor cell is the char it sits on.
        let segments = prompt_segments("kuzushi> ", "abcdef", 4, 40, " ");
        assert_eq!(segments.before_cursor, "abcd");
        assert_eq!(segments.cursor_text, "e");
        assert_eq!(segments.after_cursor, "f");

        // Cursor at the start — first char becomes the cursor cell.
        let segments = prompt_segments("kuzushi> ", "abcdef", 0, 40, " ");
        assert_eq!(segments.before_cursor, "");
        assert_eq!(segments.cursor_text, "a");
        assert_eq!(segments.after_cursor, "bcdef");

        // Cursor past the end is clamped to len so we don't panic on stale
        // indices coming from history-restore races.
        let segments = prompt_segments("kuzushi> ", "abc", 99, 40, " ");
        assert_eq!(segments.before_cursor, "abc");
        assert_eq!(segments.cursor_text, " ");
    }

    #[test]
    fn view_status_segment_reflects_actual_view_not_focused_module() {
        // P1-2: previously the bottom status footer always read "catalog"
        // while the user was on Help / Tools / Findings. Verify the helper
        // returns the real view label so the status reflects what the user
        // actually sees.
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;
        assert_eq!(view_status_segment(&app), "help");

        app.shell_view = ShellView::Tools;
        assert_eq!(view_status_segment(&app), "tools");

        app.shell_view = ShellView::Findings;
        assert_eq!(view_status_segment(&app), "findings");

        app.shell_view = ShellView::Threat(ThreatView::Stride);
        assert_eq!(view_status_segment(&app), "threats:stride");

        // Module view still surfaces the focused module so operators can
        // see which module they're driving.
        app.focused_module = Some("semgrep".to_string());
        app.shell_view = ShellView::Module;
        assert_eq!(view_status_segment(&app), "semgrep");
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn progress_bar_line_matches_design_glyphs_and_count() {
        let line = progress_bar_line(
            "semgrep",
            612,
            612,
            "done · 18 raw hits",
            ProgressKind::Done,
        );
        let text = line_text(&line);
        assert!(text.contains("semgrep"));
        assert!(text.contains("[████████████████████████]"));
        assert!(text.contains("612/612"));
        assert!(text.contains("done · 18 raw hits"));
    }

    #[test]
    fn progress_bar_line_partial_fills_proportionally() {
        let line = progress_bar_line("agentic-sast", 87, 120, "tracing…", ProgressKind::Active);
        let text = line_text(&line);
        // 87/120 = 0.725; round(0.725 * 24) = 17 filled, 7 empty
        let filled = text.matches('█').count();
        let empty = text.matches('░').count();
        assert_eq!(filled, 17, "expected 17 filled bars: {text:?}");
        assert_eq!(empty, 7, "expected 7 empty bars: {text:?}");
        assert!(text.contains("87/120"));
    }

    #[test]
    fn progress_bar_line_zero_total_renders_empty() {
        let line = progress_bar_line("idle", 0, 0, "queued", ProgressKind::Failing);
        let text = line_text(&line);
        assert_eq!(text.matches('█').count(), 0);
        assert_eq!(text.matches('░').count(), 24);
    }

    #[test]
    fn section_header_uppercases_and_pads_dashes() {
        let line = section_header_line("findings · 11 triaged", 60);
        let text = line_text(&line);
        assert!(text.starts_with("FINDINGS · 11 TRIAGED"));
        assert!(text.ends_with("─"));
        assert_eq!(text.chars().count(), 60);
    }

    #[test]
    fn compact_finding_row_renders_alias_severity_and_location() {
        let line = compact_finding_row(
            "F-0001",
            Severity::Critical,
            "sql injection via order_id concatenation",
            "apps/api/orders.rs:142",
            120,
        );
        let text = line_text(&line);
        assert!(text.contains("F-0001"));
        assert!(text.contains("CRITICAL"));
        assert!(text.contains("sql injection via order_id"));
        assert!(text.contains("apps/api/orders.rs:142"));
    }
}
