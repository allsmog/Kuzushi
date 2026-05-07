use super::*;

pub(in crate::renderer) fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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
    lines.push(aligned_header(
        &["", "#", "model", "effort", "auth"],
        &widths,
    ));
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
    lines.push(command_list_line(
        &[
            "Up/Down select",
            "Enter choose",
            "model <n> [xhigh]",
            "auth login openai-codex|anthropic",
        ],
        area.width as usize,
    ));
    lines
}

pub(in crate::renderer) fn model_auth_status(choice: &crate::app::ModelChoice) -> String {
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

pub(in crate::renderer) fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TOOLS", area.width));
    let widths = [28usize, 8, value_width(area, 38)];
    lines.push(aligned_header(
        &["tool", "headless", "description"],
        &widths,
    ));
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

pub(in crate::renderer) fn auth_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    // PROVIDERS section --------------------------------------------------
    lines.push(divider("PROVIDERS", area.width));
    let providers = auth_provider_rows(app);
    for row in &providers {
        lines.push(auth_provider_line(row));
    }
    lines.push(blank());

    // MODEL · effective section -----------------------------------------
    lines.push(divider("MODEL · effective", area.width));
    let model = app.config.model.as_deref().unwrap_or("unconfigured");
    let backend = crate::app::runtime_backend_label(&app.config);
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("current  ", theme::muted()),
        Span::styled(model.to_string(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("backend ", theme::muted()),
        Span::styled(backend.to_string(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("routing ", theme::muted()),
        Span::styled("direct", theme::primary()),
    ]));
    if let Some(reasoning) = app.session_thinking_level.as_deref() {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled("reasoning ", theme::muted()),
            Span::styled(reasoning.to_string(), theme::primary()),
        ]));
    }
    lines.push(blank());

    // SPEND section ------------------------------------------------------
    lines.push(divider("SPEND · this session", area.width));
    let session_cost = format_session_cost(app.session_cost_usd);
    let last_tool = app
        .last_tool_cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("session   ", theme::muted()),
        Span::styled(session_cost, theme::primary()),
        Span::styled("   · ", theme::subtle()),
        Span::styled("last tool ", theme::muted()),
        Span::styled(last_tool, theme::primary()),
    ]));
    if let Some(budget) = app.session_budget_usd {
        let pct = if budget > 0.0 {
            (app.session_cost_usd / budget * 100.0).round() as usize
        } else {
            0
        };
        let pct_style = if pct >= 85 {
            theme::warn()
        } else {
            theme::muted()
        };
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled("budget    ", theme::muted()),
            Span::styled(format!("${budget:.2}"), theme::primary()),
            Span::styled("   · ", theme::subtle()),
            Span::styled(format!("{pct}%"), pct_style),
        ]));
    }
    lines.push(blank());

    // CTA row
    lines.push(command_list_line(
        &[
            "auth login openai-codex",
            "auth login anthropic",
            "model <provider:id>",
            "config",
            "back",
        ],
        area.width as usize,
    ));
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::renderer) enum AuthProviderState {
    Connected,
    Missing,
    Inactive,
}

pub(in crate::renderer) struct AuthProviderRow {
    name: &'static str,
    state: AuthProviderState,
    detail: String,
}

/// Build the providers table for `auth_lines`.  Keeps the data source
/// honest: `KUZUSHI_API_KEY` / `ANTHROPIC_API_KEY` for env-key auth,
/// `oauth_provider_status` for OAuth.
pub(in crate::renderer) fn auth_provider_rows(app: &ShellApp) -> Vec<AuthProviderRow> {
    let api_key_env = app.config.runtime.api_key_env.clone();
    let env_set = std::env::var_os(api_key_env.as_str()).is_some();
    let anthropic_set = std::env::var_os("ANTHROPIC_API_KEY").is_some();
    let codex_oauth = crate::app::oauth_provider_status("openai-codex");
    let anthropic_oauth = crate::app::oauth_provider_status("anthropic");

    let env_state = if env_set {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Missing
    };
    let env_detail = if env_set {
        format!("{api_key_env}=set; value hidden")
    } else {
        format!("{api_key_env}=missing")
    };

    let anthropic_state = if anthropic_set || anthropic_oauth == "ok" {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Missing
    };
    let anthropic_detail = format!(
        "ANTHROPIC_API_KEY={}; oauth {}",
        if anthropic_set { "set" } else { "missing" },
        anthropic_oauth
    );

    let codex_state = if codex_oauth == "ok" {
        AuthProviderState::Connected
    } else {
        AuthProviderState::Inactive
    };
    let codex_detail = format!("oauth {codex_oauth}");

    vec![
        AuthProviderRow {
            name: "pi-agent-core",
            state: env_state,
            detail: env_detail,
        },
        AuthProviderRow {
            name: "anthropic",
            state: anthropic_state,
            detail: anthropic_detail,
        },
        AuthProviderRow {
            name: "openai-codex",
            state: codex_state,
            detail: codex_detail,
        },
    ]
}

pub(in crate::renderer) fn auth_provider_line(row: &AuthProviderRow) -> Line<'static> {
    let (glyph, glyph_style, label_style) = match row.state {
        AuthProviderState::Connected => (" ✓ ", theme::success(), theme::success()),
        AuthProviderState::Missing => (" ✗ ", theme::danger(), theme::danger()),
        AuthProviderState::Inactive => (" · ", theme::subtle(), theme::muted()),
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, glyph_style),
        Span::raw(" "),
        Span::styled(format!("{:14}", row.name), theme::accent()),
        Span::styled(format!("{:11}", row.state.label()), label_style),
        Span::styled(row.detail.clone(), theme::muted()),
    ])
}

impl AuthProviderState {
    fn label(self) -> &'static str {
        match self {
            AuthProviderState::Connected => "connected",
            AuthProviderState::Missing => "missing",
            AuthProviderState::Inactive => "inactive",
        }
    }
}

/// `/patch <alias>` view — RATIONALE / DIFF / TESTS / GUARDRAIL
/// matching `design/mockups/patch.jsx`.  Pulls from
/// `app.pending_patch` when the alias matches; otherwise renders an
/// empty state advising how to stage a patch.

pub(in crate::renderer) fn cost_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    // BUDGETS section ----------------------------------------------------
    lines.push(divider("BUDGETS", area.width));
    let session = app.session_cost_usd;
    let session_budget = app.session_budget_usd.unwrap_or(5.0);
    lines.push(cost_budget_bar("this session    ", session, session_budget));
    if let Some(last) = app.last_tool_cost_usd {
        lines.push(cost_budget_bar("last tool       ", last, session_budget));
    }
    lines.push(blank());

    // SPEND section ------------------------------------------------------
    lines.push(divider("SPEND", area.width));
    let session_text = format_session_cost(session);
    let last_text = app
        .last_tool_cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    lines.push(detail("session", &session_text));
    lines.push(detail("last tool", &last_text));
    if let Some(budget) = app.session_budget_usd {
        lines.push(detail("budget", &format!("${budget:.2}")));
    } else {
        lines.push(detail("budget", "unset"));
    }
    lines.push(blank());

    // CTA row
    lines.push(command_list_line(
        &["model <provider:id>", "config", "back"],
        area.width as usize,
    ));
    lines.push(muted(
        "Per-tool spend ledger appears once Rust tools report `costUsd` (scanner-only work may stay $0).",
    ));
    lines
}

/// Render a single 30-cell budget bar matching
/// `design/mockups/cost.jsx::bar`.  Bar is severity-tinted by spend
/// percentage (success < 85% < warn < 100% < danger).
pub(in crate::renderer) fn cost_budget_bar(label: &str, used: f64, cap: f64) -> Line<'static> {
    let bar_w: usize = 30;
    let pct = if cap > 0.0 {
        (used / cap).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let fill = (bar_w as f64 * pct).round() as usize;
    let empty = bar_w - fill;
    let pct_int = (pct * 100.0).round() as usize;
    let style = if pct_int >= 100 {
        theme::danger()
    } else if pct_int >= 85 {
        theme::warn()
    } else {
        theme::success()
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:18}", label), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(fill), style),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(format!("${used:>6.2}"), theme::primary()),
        Span::styled(" / ", theme::muted()),
        Span::styled(format!("${cap:>6.2}"), theme::muted()),
        Span::raw(" "),
        Span::styled(format!("{pct_int:>3}%"), style),
    ])
}
