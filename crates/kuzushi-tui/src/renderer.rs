use std::collections::BTreeMap;

use kuzushi_core::modules::ModuleKind;
use kuzushi_core::{Finding, Severity};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span, Style};
use ratatui::widgets::Paragraph;

use crate::app::{ScanPanelState, ShellApp, ShellView, ThreatView};
use crate::theme;

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let view_lines = shell_view_lines(app, area);
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
    let fixed_height = prompt_height + transcript_height + keybind_height + status_height;
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let view_height = (view_lines.len() as u16).clamp(1, max_view_height);

    let mut constraints = vec![Constraint::Length(view_height)];
    if status_height > 0 {
        constraints.push(Constraint::Length(status_height));
    }
    if keybind_height > 0 {
        constraints.push(Constraint::Length(keybind_height));
    }
    if transcript_height > 0 {
        constraints.push(Constraint::Length(transcript_height));
    }
    constraints.push(Constraint::Length(prompt_height));
    constraints.push(Constraint::Min(0));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut index = 0;
    render_lines(frame, chunks[index], view_lines);
    index += 1;

    if status_height > 0 {
        render_status_footer(frame, chunks[index], app);
        index += 1;
    }
    if keybind_height > 0 {
        render_keybind_footer(frame, chunks[index], app);
        index += 1;
    }
    if transcript_height > 0 {
        render_transcript(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
}

fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match &app.shell_view {
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
        ShellView::Help => help_lines(app, area),
        ShellView::Config => config_lines(app, area),
        ShellView::Tools => tools_lines(app, area),
    }
}

fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
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
                "[!] no app context built yet - run scan after selecting a target",
                theme::warn(),
            ));
        }
        lines.push(muted(
            "Type help, modules, use <module>, scan, or run <tool> [json].",
        ));
        return lines;
    }

    if let Some(module) = modules
        .iter()
        .find(|module| module.metadata().id == "semgrep")
        .or_else(|| modules.first())
    {
        let hint = format!(
            "Recommended first: use {} - {}",
            module.metadata().id,
            short_sentence(&module.metadata().description, 88)
        );
        lines.push(styled(&fit(&hint, area.width as usize), theme::primary()));
        lines.push(blank());
    }

    let mut grouped: BTreeMap<&'static str, Vec<_>> = BTreeMap::new();
    for module in modules {
        grouped
            .entry(module_category(module.metadata().kind).0)
            .or_default()
            .push(module);
    }

    for category in ["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"] {
        let Some(rows) = grouped.get(category) else {
            continue;
        };
        let (_, blurb) = module_category_blurb(category);
        let widths = module_table_widths(area.width);
        lines.push(divider(category, area.width));
        lines.push(indent(
            muted(&fit(blurb, area.width.saturating_sub(2) as usize)),
            2,
        ));
        lines.push(table_header(&["id", "description", "dag"], &widths));
        for module in rows {
            let dag = if module.dag_nodes().is_empty() {
                "-"
            } else {
                "yes"
            };
            lines.push(table_row(
                &[&module.metadata().id, &module.metadata().description, dag],
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
    lines.push(Line::from(vec![
        Span::styled(module.metadata().id.clone(), theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.metadata().name.clone(), theme::muted()),
    ]));
    lines.push(muted(&short_sentence(
        &module.metadata().description,
        area.width as usize,
    )));
    lines.push(blank());

    if module.tools().is_empty() {
        lines.push(muted("No shell tools are exposed by this module."));
    } else {
        lines.push(divider("TOOLS", area.width));
        lines.push(header(&["tool", "headless", "description"]));
        for tool in module.tools() {
            lines.push(row(&[
                fit(&tool.name, 24),
                tool.headless.to_string(),
                fit(&tool.description, value_width(area, 42)),
            ]));
        }
    }

    if !module.dag_nodes().is_empty() {
        lines.push(blank());
        lines.push(divider("DAG", area.width));
        lines.push(header(&["node", "output", "depends on"]));
        for node in module.dag_nodes() {
            lines.push(row(&[
                fit(&node.id, 24),
                fit(&node.output_kind, 12),
                fit(&node.depends_on.join(", "), value_width(area, 42)),
            ]));
        }
    }

    lines
}

fn module_run_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
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
        .unwrap_or_else(|| "run pending".to_string());

    lines.push(Line::from(vec![
        Span::styled("● ", theme::accent()),
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
    lines.push(pipeline_row(
        if active_stage.contains("context") {
            "→"
        } else {
            "✓"
        },
        "context-lite:index",
        if active_stage.contains("context") {
            "active"
        } else {
            "ready"
        },
    ));
    lines.push(pipeline_row(
        if scan.is_some_and(|scan| scan.running) {
            "→"
        } else {
            "✓"
        },
        "semgrep:scan",
        active_stage,
    ));
    lines.push(pipeline_row(
        "○",
        "triage:run",
        if findings > 0 {
            "queued"
        } else {
            "waiting for findings"
        },
    ));

    if let Some(error) = scan.and_then(|scan| scan.error.as_ref()) {
        lines.push(blank());
        lines.push(Line::from(vec![
            Span::styled("error ", theme::danger()),
            Span::raw(fit(error, area.width.saturating_sub(6) as usize)),
        ]));
    }

    lines.push(blank());
    lines.push(divider("TRANSCRIPT", area.width));
    lines.extend(transcript_lines(
        app,
        area.height.saturating_sub(lines.len() as u16) as usize,
    ));
    lines
}

fn findings_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled("filters ", theme::label()),
        Span::styled("[all] ", theme::selection()),
        Span::styled("[critical] [high] [medium] [low]", theme::muted()),
    ]));
    lines.push(blank());

    if app.findings.is_empty() {
        lines.push(muted("No findings yet."));
        lines.push(muted(
            "Run scan to populate the workspace findings database.",
        ));
        return lines;
    }

    lines.push(header(&["alias", "severity", "location", "title"]));
    for (index, finding) in app.findings.iter().enumerate() {
        let alias = format!("F-{number:04}", number = index + 1);
        let selected = app
            .selected_finding
            .as_ref()
            .is_some_and(|selected| selected.fingerprint == finding.fingerprint);
        let marker = if selected { ">" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(marker, theme::subtle()),
            Span::raw(" "),
            Span::styled(pad(&alias, 9), theme::accent()),
            Span::styled(
                pad(finding.severity.as_str(), 10),
                theme::severity(finding.severity),
            ),
            Span::styled(
                pad(
                    &fit(&format!("{}:{}", finding.file_path, finding.start_line), 30),
                    32,
                ),
                theme::muted(),
            ),
            Span::raw(fit(&finding.title, value_width(area, 55))),
        ]));
    }

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
    lines.push(muted(
        "Use prompt edit <verb> for prompt overrides and back to return.",
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
            lines.push(divider("DFD", area.width));
            lines.push(detail(
                "external",
                "browser, API clients, package registries",
            ));
            lines.push(detail("application", "source tree, handlers, jobs, CLIs"));
            lines.push(detail("datastore", "SQLite state, config, run artifacts"));
            lines.push(blank());
            lines.push(Line::raw("external -> application -> datastore"));
        }
        ThreatView::Stride => {
            lines.push(divider("STRIDE", area.width));
            lines.push(header(&["element", "S", "T", "R", "I", "D", "E"]));
            for element in ["entrypoints", "auth", "storage", "scanners"] {
                lines.push(row(&[
                    pad(element, 16),
                    "med".to_string(),
                    "high".to_string(),
                    "low".to_string(),
                    "med".to_string(),
                    "low".to_string(),
                    "med".to_string(),
                ]));
            }
        }
        ThreatView::Stories => {
            lines.push(divider("STORIES", area.width));
            lines.push(detail(
                "A1",
                "malicious input reaches a sink through an unvalidated handler",
            ));
            lines.push(detail(
                "A2",
                "dependency behavior changes scanner or runtime assumptions",
            ));
            lines.push(detail(
                "A3",
                "local secrets leak through logs, artifacts, or prompt context",
            ));
        }
        ThreatView::Scope => {
            lines.push(divider("SCOPE", area.width));
            lines.push(detail(
                "critical",
                "auth, request parsing, code execution paths",
            ));
            lines.push(detail(
                "high",
                "persistence, background jobs, external tools",
            ));
            lines.push(detail(
                "out of scope",
                "generated caches, vendored fixtures",
            ));
        }
        ThreatView::Summary => {
            lines.push(divider("SUMMARY", area.width));
            lines.push(detail("elements", "4"));
            lines.push(detail("stories", "3"));
            lines.push(detail("highest risk", "scanners -> subprocess boundary"));
            lines.push(detail("artifact", ".kuzushi/threat-model.json"));
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
    lines.push(header(&["verb", "source", "override path"]));
    for verb in ["scan", "triage", "verify", "summary"] {
        lines.push(row(&[
            pad(verb, 12),
            "builtin".to_string(),
            fit(
                &format!(".kuzushi/prompts/{module}/{verb}.md"),
                value_width(area, 28),
            ),
        ]));
    }
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
    lines.push(blank());
    lines.extend(transcript_lines(
        app,
        area.height.saturating_sub(6) as usize,
    ));
    lines
}

fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUNS", area.width));
    if let Some(scan) = &app.scan {
        lines.push(header(&["run", "status", "findings", "target"]));
        lines.push(row(&[
            scan.run_id
                .as_deref()
                .map(short)
                .unwrap_or_else(|| "pending".to_string()),
            scan_status(scan),
            scan.findings_count.to_string(),
            fit(&scan.target.display().to_string(), value_width(area, 34)),
        ]));
    } else {
        lines.push(muted("No scan run is active in this shell session."));
    }
    lines
}

fn replay_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPLAY", area.width));
    lines.push(detail("run", run_id));
    lines.push(detail(
        "summary",
        &format!(".kuzushi/runs/{run_id}/summary.json"),
    ));
    lines.push(detail(
        "triage",
        &format!(".kuzushi/runs/{run_id}/triage.jsonl"),
    ));
    lines
}

fn trace_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TRACE", area.width));
    lines.push(detail("run", run_id));
    lines.push(detail(
        "triage",
        &format!(".kuzushi/runs/{run_id}/triage.jsonl"),
    ));
    lines.push(detail(
        "verify",
        &format!(".kuzushi/runs/{run_id}/verify.jsonl"),
    ));
    lines
}

fn help_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HELP", area.width));
    for (command, description) in [
        ("modules", "browse native modules"),
        ("use <module>", "focus a module"),
        ("scan [target]", "run configured scanners"),
        ("findings", "open persisted findings"),
        ("open <id>", "open a finding"),
        ("tune", "module controls"),
        ("threats [1-5]", "threat model views"),
        ("prompts", "prompt overrides"),
        ("show runs", "recent run artifacts"),
        ("replay <run>", "render a run summary"),
        ("trace <run>", "stream run events"),
        ("back", "return to the previous shell view"),
        ("quit", "exit"),
    ] {
        lines.push(row(&[pad(command, 18), description.to_string()]));
    }
    lines
}

fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("CONFIG", area.width));
    lines.push(detail("runtime", &format!("{:?}", app.config.runtime.kind)));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(detail(
        "base url",
        app.config
            .runtime
            .base_url
            .as_deref()
            .unwrap_or("provider default"),
    ));
    lines
}

fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TOOLS", area.width));
    lines.push(header(&["tool", "headless", "description"]));
    for tool in app.registry.tools() {
        lines.push(row(&[
            fit(&tool.name, 24),
            tool.headless.to_string(),
            fit(&tool.description, value_width(area, 40)),
        ]));
    }
    lines
}

fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let left = if app.scan.as_ref().is_some_and(|scan| scan.running) {
        join_segments(&[
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            app.scan
                .as_ref()
                .map(scan_status)
                .unwrap_or_else(|| "idle".to_string()),
        ])
    } else {
        join_segments(&[
            app.target
                .as_ref()
                .map(|path| compact_target_path(&path.display().to_string()))
                .unwrap_or_else(|| "target:none".to_string()),
            "ctx: missing".to_string(),
            app.focused_module
                .clone()
                .unwrap_or_else(|| "catalog".to_string()),
        ])
    };

    let right = join_segments(&[findings_summary(&app.findings)]);
    let text = justify(left, right, area.width as usize);
    frame.render_widget(Paragraph::new(Line::styled(text, theme::primary())), area);
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
        lines.push(Line::styled(
            keybindings_text(app, area.width as usize),
            theme::primary(),
        ));
    }

    render_lines(frame, area, lines);
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

    let prompt = if let Some(module) = &app.focused_module {
        format!("kuzushi/{module}> ")
    } else {
        "kuzushi> ".to_string()
    };
    let segments = prompt_segments(&prompt, &app.input, area.width as usize, " ");
    let line = Line::from(vec![
        Span::styled(segments.prompt, theme::label()),
        Span::raw(segments.before_cursor),
        Span::styled(segments.cursor_text, theme::selection()),
        Span::raw(segments.after_cursor),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let target = app
        .target
        .as_ref()
        .map(|path| {
            format!(
                "target:{}",
                compact_target_path(&path.display().to_string())
            )
        })
        .unwrap_or_else(|| "target:none".to_string());
    let module = app
        .focused_module
        .clone()
        .unwrap_or_else(|| "catalog".to_string());
    let module_count = app.registry.modules().count();
    let findings = findings_count_summary(&app.findings);

    vec![status_line(
        &[target, module, format!("{module_count} modules"), findings],
        area.width,
    )]
}

fn transcript_lines(app: &ShellApp, visible: usize) -> Vec<Line<'static>> {
    if visible == 0 {
        return Vec::new();
    }
    let start = app.log.len().saturating_sub(visible);
    app.log[start..]
        .iter()
        .map(|line| {
            Line::from(vec![
                Span::styled(format!("{:>8} ", line.prefix), theme::subtle()),
                Span::raw(line.body.clone()),
            ])
        })
        .collect()
}

fn keybindings_text(app: &ShellApp, width: usize) -> String {
    let bindings = keybindings(app);
    let mut shown = Vec::new();
    for (key, label) in bindings {
        let next = format!("[{key}] {label}");
        let candidate = if shown.is_empty() {
            next.clone()
        } else {
            format!("{}  ·  {next}", shown.join("  ·  "))
        };
        if candidate.chars().count() > width.saturating_sub(8) && !shown.is_empty() {
            shown.push("+more".to_string());
            break;
        }
        shown.push(next);
    }
    fit(&shown.join("  ·  "), width)
}

fn keybindings(app: &ShellApp) -> Vec<(&'static str, &'static str)> {
    if app.scan.as_ref().is_some_and(|scan| scan.running) {
        return vec![
            ("Ctrl+C", "abort scan"),
            ("actor 1", "actor detail"),
            ("findings", "findings"),
            ("back", "home"),
        ];
    }

    match app.shell_view {
        ShellView::Catalog if !app.catalog_expanded => vec![
            ("modules", "browse"),
            ("use <id>", "focus module"),
            ("scan", "scan target"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Catalog => vec![
            ("use <id>", "focus module"),
            ("findings", "findings"),
            ("help", "help"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Findings => vec![
            ("open <id>", "open finding"),
            ("scan", "rescan"),
            ("back", "home"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Finding => vec![
            ("back", "findings"),
            ("findings", "list"),
            ("scan", "rescan"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Threat(_) => vec![
            ("1..5", "switch threat view"),
            ("threats edit", "edit"),
            ("back", "home"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::PromptsEditor => vec![
            ("prompt edit", "edit"),
            ("prompt show", "show"),
            ("back", "module"),
            ("Ctrl+C", "exit"),
        ],
        _ => vec![
            ("Enter", "run command"),
            ("back", "home"),
            ("help", "help"),
            ("Ctrl+C", "exit"),
        ],
    }
}

fn render_lines(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn status_line(items: &[String], width: u16) -> Line<'static> {
    Line::styled(fit(&join_segments(items), width as usize), theme::primary())
}

fn detail(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key} "), theme::label()),
        Span::raw(value.to_string()),
    ])
}

fn divider(title: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let title = format!(" {title} ");
    let remaining = safe_width.saturating_sub(title.chars().count());
    let left = remaining / 2;
    let right = remaining.saturating_sub(left);
    Line::from(vec![
        Span::styled(theme::RULE_CHAR.repeat(left), theme::subtle()),
        Span::styled(title, theme::muted()),
        Span::styled(theme::RULE_CHAR.repeat(right), theme::subtle()),
    ])
}

fn module_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = if total < 72 { 14 } else { 22 };
    let dag = 3;
    let gaps = 4;
    let description = total.saturating_sub(id + dag + gaps).max(16);
    vec![id, description, dag]
}

fn table_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    Line::styled(table_text(values, widths), theme::subtle())
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

fn header(values: &[&str]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .map(|value| Span::styled(format!("{}  ", pad(value, 14)), theme::subtle()))
            .collect::<Vec<_>>(),
    )
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

fn pipeline_row(symbol: &str, label: &str, detail: &str) -> Line<'static> {
    let style = match symbol {
        "✓" => theme::success(),
        "→" => theme::accent(),
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
        "OFFENSE" => ("OFFENSE", "hunt vulnerabilities and prove exploitability"),
        "INTEL" => (
            "INTEL",
            "research targets, map attack surface, gather context",
        ),
        "GOVERNANCE" => ("GOVERNANCE", "policy, config, and audit-ready evidence"),
        "DEFENSE" => ("DEFENSE", "detect, prioritize, and remediate findings"),
        _ => ("OTHER", "loaded module surfaces"),
    }
}

fn scan_status(scan: &ScanPanelState) -> String {
    if scan.running {
        format!("running: {}", scan.stage)
    } else {
        scan.stage.clone()
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

fn justify(left: String, right: String, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let left = fit(&left, width);
    if right.is_empty() {
        return left;
    }
    let right = fit(&right, width);
    let left_len = left.chars().count();
    let right_len = right.chars().count();
    if left_len + right_len + 1 >= width {
        return fit(&format!("{left} {}", right), width);
    }
    format!(
        "{left}{}{}",
        " ".repeat(width - left_len - right_len),
        right
    )
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

fn pad(value: &str, width: usize) -> String {
    let value = fit(value, width);
    let padding = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(padding))
}

fn value_width(area: Rect, used: usize) -> usize {
    (area.width as usize).saturating_sub(used).max(12)
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
    columns: usize,
    cursor_glyph: &str,
) -> PromptSegments {
    let width = columns.max(1);
    let min_editor_width = 2.min(width);
    let fitted_prompt = fit_prompt(prompt, width.saturating_sub(min_editor_width));
    let editor_width = width.saturating_sub(fitted_prompt.chars().count()).max(1);

    let input_chars = input.chars().collect::<Vec<_>>();
    let cursor = input_chars.len();
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
    use kuzushi_core::{Finding, Severity, V2Config};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    #[test]
    fn renders_ink_style_shell_without_box_dashboard() {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ShellApp::new(V2Config::default(), None);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("kuzushi shell"));
        assert!(rendered.contains("kuzushi>"));
        assert!(rendered.contains("[modules]"));
        assert!(!rendered.contains("command log"));
        assert!(!rendered.contains("┌"));
        assert!(!rendered.contains("v2"));
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
        assert!(rendered.contains("fingerprint"));
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
    fn renders_threat_view_navigation() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stride);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("STRIDE"));
        assert!(rendered.contains("entrypoints"));
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
        assert!(rendered.contains("description"));
        assert!(!rendered.contains("module context-lite"));
        assert!(!rendered.contains("command log"));
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
        ];

        for (view, expected) in cases {
            let backend = TestBackend::new(110, 26);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            app.focused_module = Some("semgrep".to_string());
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(expected), "missing {expected}");
            assert!(!rendered.contains("┌"));
        }
    }
}
