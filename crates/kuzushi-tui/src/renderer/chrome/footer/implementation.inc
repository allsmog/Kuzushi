use super::*;

pub(in crate::renderer) fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
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
    } else if let Some(tool_name) = app.running_tool_name() {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.tool_abort_requested() {
                format!("{tool_name}: abort requested")
            } else {
                format!("{tool_name}: active")
            },
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

pub(in crate::renderer) fn justify_prefer_right(
    left: String,
    right: String,
    width: usize,
) -> String {
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

pub(in crate::renderer) fn render_keybind_footer(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
) {
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
pub(in crate::renderer) fn keybindings_line(app: &ShellApp, width: usize) -> Line<'static> {
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

pub(in crate::renderer) fn keybindings(app: &ShellApp) -> Vec<(&'static str, &'static str)> {
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
    if app.running_tool_name().is_some() {
        return vec![
            (
                "Ctrl+C",
                if app.tool_abort_requested() {
                    "arm exit"
                } else {
                    "request abort"
                },
            ),
            ("findings", "list"),
            ("back", "home"),
            ("history", "events"),
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
            ("j/k", "row"),
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("findings", "findings"),
            ("?", "help"),
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

pub(in crate::renderer) fn push_view_keybindings(
    bindings: &mut Vec<(&'static str, &'static str)>,
    app: &ShellApp,
) {
    for binding in app.view_keybindings() {
        if !bindings
            .iter()
            .any(|(hint, label)| *hint == binding.hint && *label == binding.label)
        {
            bindings.push((binding.hint, binding.label));
        }
    }
}
