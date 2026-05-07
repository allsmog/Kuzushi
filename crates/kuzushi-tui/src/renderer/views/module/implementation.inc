use super::*;
use crate::app::SastTaskRow;

pub(in crate::renderer) fn module_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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

    // OPTIONS — set values from the option store, per
    // `design/mockups/modules-detail.jsx::s2`.  Only show options that
    // actually have stored values; keep the panel terse for modules
    // that haven't been tuned.
    let stored_options = module_stored_options(app, module);
    if !stored_options.is_empty() {
        lines.push(divider(
            &format!("OPTIONS · {}", stored_options.len()),
            area.width,
        ));
        for (name, value) in &stored_options {
            lines.push(detail(name, value));
        }
        lines.push(blank());
    }

    // PROMPTS — `.kuzushi/prompts/<module>/<verb>.md` files on disk.
    // Lists prompt verbs the operator has overridden so they can jump
    // to the editor with `prompt edit <verb>`.
    let prompts = module_prompts_on_disk(app, &module.metadata().id);
    if !prompts.is_empty() {
        lines.push(divider(&format!("PROMPTS · {}", prompts.len()), area.width));
        for prompt in &prompts {
            lines.push(detail(&prompt.verb, &prompt.path));
        }
        lines.push(blank());
    }

    // STATS — quick session-level counts the operator can verify
    // without scrubbing the transcript.  Pulls live data only.
    let module_log_count = app
        .log
        .iter()
        .filter(|line| {
            line.prefix == module.metadata().id
                || line
                    .prefix
                    .starts_with(&format!("{}:", module.metadata().id))
        })
        .count();
    if module_log_count > 0 {
        lines.push(divider("STATS · this session", area.width));
        lines.push(detail(
            "log entries",
            &format!("{module_log_count} from `{}`", module.metadata().id),
        ));
        lines.push(detail("tools bound", &module.tools().len().to_string()));
        lines.push(blank());
    }
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
        primary_tool,
        area.width,
    ));

    lines
}

/// Returns `(option-name, formatted-value)` for every tool-scoped
/// option in this module that has a stored value in the session/global
/// option store.  Used by `module_lines` OPTIONS section to mirror
/// `design/mockups/modules-detail.jsx::s2`.
pub(in crate::renderer) fn module_stored_options(
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for tool in module.tools() {
        let stored = app.option_store.effective_stored_values(&tool.name);
        for (name, value) in stored.iter() {
            out.push((format!("{}::{}", tool.name, name), format_json_value(value)));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[derive(Debug, Clone)]
pub(in crate::renderer) struct ModulePromptOnDisk {
    verb: String,
    path: String,
}

/// Walk `<target>/.kuzushi/prompts/<module>/` and return every `*.md`
/// file as (verb, relative-path).  Per the agent guide in `CLAUDE.md`
/// this is exactly the directory `executeTool` reads from for prompt
/// overrides.  Empty when the dir doesn't exist.
pub(in crate::renderer) fn module_prompts_on_disk(
    app: &ShellApp,
    module_id: &str,
) -> Vec<ModulePromptOnDisk> {
    let prompts_root = app
        .target
        .as_deref()
        .map(|t| t.join(".kuzushi/prompts").join(module_id))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/prompts").join(module_id));
    let Ok(entries) = std::fs::read_dir(&prompts_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".md") {
            continue;
        }
        let verb = name.trim_end_matches(".md").to_string();
        out.push(ModulePromptOnDisk {
            verb,
            path: entry
                .path()
                .strip_prefix(app.target.as_deref().unwrap_or(std::path::Path::new(".")))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| entry.path().display().to_string()),
        });
    }
    out.sort_by(|a, b| a.verb.cmp(&b.verb));
    out
}

/// Pull the most recent N log lines that look like they came from the given
/// module (by prefix or body match). Returns oldest-first.
pub(in crate::renderer) fn recent_module_log(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<(String, String)> {
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
pub(in crate::renderer) fn recent_module_activity_lines(
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
pub(in crate::renderer) fn recon_snapshot_lines(
    snapshot: &crate::app::ReconSnapshot,
    take: usize,
) -> Vec<Line<'static>> {
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
/// Transcript-style finding row with severity tint.  Mirrors the mockup
/// finding row colour split (`design/mockups/findings.jsx::findingRow`):
///
///   `▸ <severity>  <rule-id>  <path>:<line>`
///   warn glyph + severity-tinted severity + accent rule-id + muted location.
pub(in crate::renderer) fn transcript_finding_line(
    severity: Severity,
    rule_id: &str,
    file_path: &str,
    line: u32,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(" ▸ ", theme::warn()),
        Span::styled(
            format!("{:9}", severity.as_str().to_uppercase()),
            theme::severity(severity),
        ),
        Span::raw(" "),
        Span::styled(rule_id.to_string(), theme::accent()),
        Span::raw("  "),
        Span::styled(format!("{file_path}:{line}"), theme::muted()),
    ])
}

pub(in crate::renderer) fn carlini_snapshot_lines(
    report: &kuzushi_core::CarliniThreatHuntReport,
) -> Vec<Line<'static>> {
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
        lines.push(transcript_finding_line(
            finding.severity,
            &finding.rule_id,
            &finding.file_path,
            finding.start_line,
        ));
    }
    lines
}

/// Format an agentic-sast snapshot as a one-line summary plus up to
/// five top finding rows. Mirrors the `AgenticSastReport::output` shape
/// but as styled transcript lines.
pub(in crate::renderer) fn agentic_sast_snapshot_lines(
    report: &kuzushi_core::AgenticSastReport,
) -> Vec<Line<'static>> {
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
        lines.push(transcript_finding_line(
            finding.severity,
            &finding.rule_id,
            &finding.file_path,
            finding.start_line,
        ));
    }
    lines
}

struct ModuleRunSummary {
    target: String,
    stage: String,
    findings: usize,
    run: String,
    active_stage: String,
    scan_running: bool,
    scan_done: bool,
    has_scan: bool,
    running_tool: Option<String>,
    scan_error: Option<String>,
}

impl ModuleRunSummary {
    fn from_app(app: &ShellApp) -> Self {
        let scan = app.scan.as_ref();
        let running_tool = app.running_tool_name().map(str::to_string);
        let target = scan
            .map(|scan| compact_target_path(&scan.target.display().to_string()))
            .or_else(|| {
                app.target
                    .as_ref()
                    .map(|path| compact_target_path(&path.display().to_string()))
            })
            .unwrap_or_else(|| "target:none".to_string());
        let stage = scan
            .map(scan_status)
            .or_else(|| running_tool.as_ref().map(|_| "running".to_string()))
            .unwrap_or_else(|| "idle".to_string());
        let findings = scan
            .map(|scan| scan.findings_count)
            .unwrap_or(app.findings.len());
        let run = scan
            .and_then(|scan| scan.run_id.as_ref())
            .map(|run_id| format!("run {}", short(run_id)))
            .unwrap_or_else(|| run_label_without_id(scan.is_some(), running_tool.as_deref()));
        let active_stage = scan
            .map(|scan| scan.stage.clone())
            .unwrap_or_else(|| "idle".to_string());
        let scan_running = scan.is_some_and(|scan| scan.running);
        let scan_done =
            scan.is_some() && !scan_running && scan.and_then(|scan| scan.error.as_ref()).is_none();
        let scan_error = scan.and_then(|scan| scan.error.clone());

        Self {
            target,
            stage,
            findings,
            run,
            active_stage,
            scan_running,
            scan_done,
            has_scan: scan.is_some(),
            running_tool,
            scan_error,
        }
    }

    fn tool_is_running(&self) -> bool {
        self.running_tool.is_some()
    }
}

fn run_label_without_id(has_scan: bool, running_tool: Option<&str>) -> String {
    if has_scan {
        "run pending".to_string()
    } else if let Some(tool_name) = running_tool {
        tool_name.to_string()
    } else {
        "tool run".to_string()
    }
}

pub(in crate::renderer) fn module_run_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let summary = ModuleRunSummary::from_app(app);

    append_run_status(
        &mut lines,
        app.scan.as_ref(),
        &summary,
        app.spinner_phase as usize,
    );
    append_progress_section(&mut lines, app, area, &summary);
    append_scan_error(&mut lines, area, &summary);
    append_findings_preview(&mut lines, app, area);

    lines.push(blank());
    lines.push(divider("TRANSCRIPT", area.width));
    let body_budget = area.height.saturating_sub(lines.len() as u16) as usize;
    let transcript = transcript_lines(app, body_budget.saturating_sub(1).max(0));
    lines.extend(transcript);
    if (summary.scan_running || summary.tool_is_running()) && body_budget > 0 {
        lines.push(streaming_cursor_line());
    }
    lines
}

fn append_run_status(
    lines: &mut Vec<Line<'static>>,
    scan: Option<&ScanPanelState>,
    summary: &ModuleRunSummary,
    spinner_phase: usize,
) {
    let tool_running = summary.tool_is_running();
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(
            run_state_glyph(scan, tool_running, spinner_phase),
            run_state_style(scan, tool_running),
        ),
        Span::raw(" "),
        Span::styled(summary.target.clone(), theme::label()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::raw(summary.stage.clone()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{} finding(s)", summary.findings), theme::muted()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(summary.run.clone(), theme::muted()),
    ]));
    lines.push(blank());
}

fn append_progress_section(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    let sast_rows = app.sast_task_rows();
    let show_per_task = sast_rows.iter().any(|row| row.selected)
        && app.focused_module.as_deref() == Some("sast")
        && (summary.scan_running || summary.scan_done);

    if append_real_scan_progress(lines, app, area, summary, show_per_task) {
        return;
    }
    if append_selected_sast_progress(lines, area, summary, &sast_rows, show_per_task) {
        return;
    }
    if app.focused_module.as_deref() == Some("sast") || summary.has_scan {
        append_sast_pipeline_progress(lines, area, summary);
        return;
    }
    if app.focused_module.as_deref() == Some("context") {
        append_context_build_progress(lines, app, area, summary);
        return;
    }
    append_generic_tool_progress(lines, app, area, summary);
}

fn append_real_scan_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
    show_per_task: bool,
) -> bool {
    if !show_per_task || app.scan_progress.is_none() {
        return false;
    }

    lines.push(divider("SCAN PROGRESS", area.width));
    let progress = app.scan_progress.as_ref().expect("checked above");
    for (task_id, (done, total)) in progress.per_task.iter() {
        let (kind, status) = scan_task_progress_state(*done, *total);
        lines.push(progress_bar_line(task_id, *done, *total, status, kind));
    }
    append_triage_progress(lines, summary.findings);
    true
}

fn scan_task_progress_state(done: usize, total: usize) -> (ProgressKind, &'static str) {
    if total == 0 {
        (ProgressKind::Queued, "queued")
    } else if done >= total {
        (ProgressKind::Done, "done")
    } else {
        (ProgressKind::Active, "running…")
    }
}

fn append_selected_sast_progress(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    summary: &ModuleRunSummary,
    sast_rows: &[SastTaskRow],
    show_per_task: bool,
) -> bool {
    if !show_per_task {
        return false;
    }

    lines.push(divider("SCAN PROGRESS", area.width));
    for row in sast_rows.iter().filter(|row| row.selected) {
        let (kind, done_count, total, status) = selected_sast_task_progress(summary.scan_done);
        lines.push(progress_bar_line(row.id, done_count, total, status, kind));
    }
    append_triage_progress(lines, summary.findings);
    true
}

fn selected_sast_task_progress(scan_done: bool) -> (ProgressKind, usize, usize, &'static str) {
    if scan_done {
        (ProgressKind::Done, 1, 1, "done")
    } else {
        (ProgressKind::Active, 0, 1, "running…")
    }
}

fn append_triage_progress(lines: &mut Vec<Line<'static>>, findings: usize) {
    let status = if findings > 0 {
        "queued after scan"
    } else {
        "waiting for findings"
    };
    let kind = if findings > 0 {
        ProgressKind::Active
    } else {
        ProgressKind::Queued
    };
    lines.push(progress_bar_line(
        "triage",
        0,
        findings.max(1),
        status,
        kind,
    ));
}

fn append_sast_pipeline_progress(
    lines: &mut Vec<Line<'static>>,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    lines.push(divider("SCAN PROGRESS", area.width));
    lines.push(pipeline_row(
        if summary.active_stage.contains("context") {
            "⏵"
        } else {
            "✓"
        },
        "context:build",
        if summary.active_stage.contains("context") {
            "active"
        } else {
            "ready"
        },
    ));
    lines.push(pipeline_row(
        sast_scan_symbol(summary),
        "sast:scan",
        &summary.active_stage,
    ));
    lines.push(pipeline_row(
        "○",
        "triage:run",
        if summary.findings > 0 {
            "queued after scan"
        } else {
            "waiting for findings"
        },
    ));
}

fn sast_scan_symbol(summary: &ModuleRunSummary) -> &'static str {
    if summary.scan_running {
        "⏵"
    } else if summary.has_scan {
        "✓"
    } else {
        "○"
    }
}

fn append_context_build_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    lines.push(divider("CONTEXT BUILD", area.width));
    if let Some(tool_name) = summary.running_tool.as_deref() {
        lines.push(pipeline_row(
            "⏵",
            tool_name,
            "indexing repository context; result will update this view",
        ));
    } else if app.context_view.exists {
        lines.push(pipeline_row("✓", "context:build", &app.context_view.status));
        if let Some(path) = app.context_view.snapshot_path.as_ref() {
            lines.push(pipeline_row("◆", "snapshot", &path.display().to_string()));
        }
    } else {
        lines.push(pipeline_row(
            "○",
            "context:build",
            "no snapshot yet; `run .` builds .kuzushi/context-snapshot.json",
        ));
    }
}

fn append_generic_tool_progress(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
    summary: &ModuleRunSummary,
) {
    let module = app.focused_module.as_deref().unwrap_or("tool");
    let running = summary.tool_is_running();
    lines.push(divider("TOOL RUN", area.width));
    lines.push(pipeline_row(
        if running { "⏵" } else { "○" },
        module,
        if running {
            "running primary tool; result will update the transcript"
        } else {
            "`run .` dispatches the module's primary tool"
        },
    ));
}

fn append_scan_error(lines: &mut Vec<Line<'static>>, area: Rect, summary: &ModuleRunSummary) {
    let Some(error) = summary.scan_error.as_ref() else {
        return;
    };

    lines.push(blank());
    let body_width = (area.width as usize).saturating_sub(6).max(20);
    let wrapped = wrap_text(error, body_width);
    for (index, segment) in wrapped.iter().enumerate() {
        lines.push(transcript_line("error", segment, index > 0));
    }
}

fn append_findings_preview(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    if app.findings.is_empty() {
        return;
    }

    lines.push(blank());
    let triaged = app
        .findings
        .iter()
        .filter(|finding| finding.triage.is_some())
        .count();
    let pending = app.findings.len().saturating_sub(triaged);
    let header = format!("FINDINGS · {triaged} triaged · {pending} pending");
    lines.push(section_header_line(&header, area.width));
    for (alias, finding) in sorted_finding_aliases(&app.findings).into_iter().take(8) {
        lines.push(compact_finding_row(
            &alias,
            finding.severity,
            &finding.title,
            &finding_location(&finding),
            area.width,
        ));
    }
    append_more_findings_hint(lines, app.findings.len());
}

fn append_more_findings_hint(lines: &mut Vec<Line<'static>>, findings_len: usize) {
    if findings_len <= 8 {
        return;
    }

    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(format!("… {} more · ", findings_len - 8), theme::muted()),
        Span::styled("/findings", theme::accent()),
        Span::styled(" to drill in", theme::muted()),
    ]));
}

/// One-row streaming cursor block — a single styled cell at the end of the
/// transcript that mirrors the design's `<span className="cursor">` from the
/// running mockups (sast-running.jsx, carlini-running.jsx, agentic-sast-running.jsx).
pub(in crate::renderer) fn streaming_cursor_line() -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            " ",
            Style::default().fg(theme::TERM_BG).bg(theme::T_PRIMARY),
        ),
    ])
}
