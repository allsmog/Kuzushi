use super::*;
use crate::ui_view_models::{
    auth_login_model, auth_provider_rows, config_model, cost_model, AuthLoginModel, ConfigModel,
    CostBudgetStatus, CostModel, CostTone,
};
use ratatui::style::Style;

/// Label column for the auth view's kv rows. Inline rows pad the first
/// label to this width so values align down a section; stacked rows (the
/// narrow-terminal fallback) pad every label to it.
const KV_LABEL_WIDTH: usize = 10;

pub(crate) fn auth_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(snapshot) = app.auth_screen_snapshot() {
        return auth_snapshot_lines(snapshot.clone(), area.width as usize);
    }

    let mut lines = context_strip(app, area);
    let config = config_model(app);
    let cost = cost_model(app);
    lines.push(blank());
    push_auth_provider_section(&mut lines, app, area);
    push_auth_login_section(&mut lines, auth_login_model(app).as_ref(), area);
    push_auth_model_section(&mut lines, &config, area);
    push_auth_spend_section(&mut lines, &cost, area);
    push_auth_rotate_section(&mut lines, area);
    push_auth_commands(&mut lines, area);
    lines
}

pub(crate) fn auth_snapshot_lines(
    snapshot: AuthScreenSnapshot,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        raw(format!(
            " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
            snapshot.status.target,
            snapshot.status.ctx,
            snapshot.status.model,
            snapshot.status.module,
            snapshot.status.cost
        )),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(snapshot.body_rows.into_iter().map(raw));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(auth_footer_stage_line(width, &snapshot.footer)));
    lines.push(raw(auth_footer_keybind_line(&snapshot.footer)));
    lines.push(raw(auth_prompt_line(&snapshot.footer)));
    lines
}

fn auth_footer_stage_line(width: usize, footer: &AuthScreenFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn auth_footer_keybind_line(footer: &AuthScreenFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn auth_prompt_line(footer: &AuthScreenFooter) -> String {
    match footer.prompt_module.as_deref() {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    }
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}

/// One `label value` cell of a kv row. Rows render inline
/// (`label value · label value`) when they fit the panel width and fall
/// back to one stacked line per pair so narrow terminals never clip a
/// value mid-word.
struct AuthKv {
    key: &'static str,
    value: String,
    style: Style,
}

fn kv(key: &'static str, value: impl Into<String>, style: Style) -> AuthKv {
    AuthKv {
        key,
        value: value.into(),
        style,
    }
}

fn kv_row(pairs: &[AuthKv], width: u16) -> Vec<Line<'static>> {
    let inline = kv_inline_line(pairs);
    if inline.width() <= width as usize {
        return vec![inline];
    }
    pairs
        .iter()
        .map(|pair| kv_stacked_line(pair, width))
        .collect()
}

fn kv_inline_line(pairs: &[AuthKv]) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (index, pair) in pairs.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        spans.push(Span::styled(
            kv_inline_label(pair.key, index),
            theme::muted(),
        ));
        spans.push(Span::styled(pair.value.clone(), pair.style));
    }
    Line::from(spans)
}

fn kv_inline_label(label: &str, index: usize) -> String {
    if index == 0 {
        kv_label_col(label)
    } else {
        format!("{label} ")
    }
}

fn kv_label_col(label: &str) -> String {
    format!("{label:<width$}", width = KV_LABEL_WIDTH)
}

fn kv_stacked_line(pair: &AuthKv, width: u16) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(kv_label_col(pair.key), theme::muted()),
        Span::styled(fit(&pair.value, kv_value_budget(width)), pair.style),
    ])
}

fn kv_value_budget(width: u16) -> usize {
    (width as usize).saturating_sub(KV_LABEL_WIDTH + 1).max(8)
}

/// Push a kv row whose value is prose (may run long): wrap it across
/// continuation lines under the label column instead of clipping.
fn push_wrapped_kv(
    lines: &mut Vec<Line<'static>>,
    label: &'static str,
    value: &str,
    style: Style,
    width: u16,
) {
    for (index, part) in wrap_text(value, kv_value_budget(width))
        .into_iter()
        .enumerate()
    {
        let lead = if index == 0 {
            kv_label_col(label)
        } else {
            " ".repeat(KV_LABEL_WIDTH)
        };
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(lead, theme::muted()),
            Span::styled(part, style),
        ]));
    }
}

fn push_auth_login_section(
    lines: &mut Vec<Line<'static>>,
    model: Option<&AuthLoginModel>,
    area: Rect,
) {
    let Some(login) = model else {
        return;
    };
    lines.push(divider("OAUTH · latest flow", area.width));
    lines.extend(kv_row(
        &[
            kv("provider", login.provider.clone(), theme::primary()),
            kv("method", login.method.clone(), theme::primary()),
            kv(
                "status",
                login.status.clone(),
                auth_login_status_style(&login.status),
            ),
        ],
        area.width,
    ));
    push_wrapped_kv(lines, "flow", &login.flow, theme::primary(), area.width);
    lines.push(auth_store_line(login, area.width));
    lines.push(blank());
}

fn auth_store_line(login: &AuthLoginModel, width: u16) -> Line<'static> {
    let inline = Line::from(vec![
        Span::raw(" "),
        Span::styled(kv_label_col("store"), theme::muted()),
        Span::styled(login.store_path.clone(), theme::primary()),
        Span::styled(" · values hidden", theme::muted()),
    ]);
    if inline.width() <= width as usize {
        return inline;
    }
    // Narrow: drop the suffix and keep the tail of the path — the file
    // name is the useful part, not the home-dir prefix.
    Line::from(vec![
        Span::raw(" "),
        Span::styled(kv_label_col("store"), theme::muted()),
        Span::styled(
            fit_path(&login.store_path, kv_value_budget(width)),
            theme::primary(),
        ),
    ])
}

fn auth_login_status_style(status: &str) -> ratatui::style::Style {
    match status {
        "connected" => theme::success(),
        "failed" => theme::danger(),
        "waiting" | "starting" => theme::warn(),
        _ => theme::muted(),
    }
}

fn push_auth_rotate_section(lines: &mut Vec<Line<'static>>, area: Rect) {
    // M3 §3.4: rotate/clear hints. Operators rotating keys mid-session
    // need to know which env var to update and how to re-auth without
    // restarting the shell. Surfaced inline so the path stays
    // self-documenting.
    lines.push(divider("ROTATE · clear & re-auth", area.width));
    for hint in [
        "unset env: `unset ANTHROPIC_API_KEY` (host shell) then re-launch kuzushi",
        "clear oauth: `auth login anthropic` or `auth login openai` to refresh",
        "switch model: `model <provider:id>` (e.g. `model anthropic:claude-opus-4-7`)",
    ] {
        push_bullet_hint(lines, hint, area.width);
    }
    lines.push(blank());
}

/// Bullet hints wrap to continuation lines under the bullet — an
/// ellipsized shell command is useless, a wrapped one still pastes.
fn push_bullet_hint(lines: &mut Vec<Line<'static>>, hint: &str, width: u16) {
    let budget = (width as usize).saturating_sub(3).max(8);
    for (index, part) in wrap_text(hint, budget).into_iter().enumerate() {
        let lead = if index == 0 { "• " } else { "  " };
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(lead.to_string(), theme::muted()),
            Span::styled(part, theme::primary()),
        ]));
    }
}

fn push_auth_provider_section(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    let providers = auth_provider_rows(app);
    let (backend_rows, provider_rows): (Vec<_>, Vec<_>) = providers
        .iter()
        .partition(|row| row.cells[0] == "LangGraph");
    if !backend_rows.is_empty() {
        lines.push(divider("BACKEND", area.width));
        for row in &backend_rows {
            lines.extend(auth_provider_lines(row, area.width));
        }
        lines.push(blank());
    }
    lines.push(divider("PROVIDERS", area.width));
    for row in &provider_rows {
        lines.extend(auth_provider_lines(row, area.width));
    }
    lines.push(blank());
}

fn push_auth_model_section(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(divider("MODEL · effective", area.width));
    lines.extend(kv_row(
        &[
            kv("current", model.model.clone(), theme::primary()),
            kv("backend", model.backend.clone(), theme::primary()),
            kv("routing", "direct", theme::primary()),
        ],
        area.width,
    ));
    lines.extend(kv_row(
        &[kv("reasoning", model.reasoning.clone(), theme::primary())],
        area.width,
    ));
    lines.push(blank());
}

fn push_auth_spend_section(lines: &mut Vec<Line<'static>>, model: &CostModel, area: Rect) {
    lines.push(divider("SPEND · this session", area.width));
    lines.extend(kv_row(
        &[
            kv(
                "session",
                model.auth_spend_cells[0].clone(),
                theme::primary(),
            ),
            kv(
                "last tool",
                model.auth_spend_cells[1].clone(),
                theme::primary(),
            ),
        ],
        area.width,
    ));
    if let Some(budget) = &model.budget_status {
        lines.extend(auth_budget_lines(budget, area.width));
    }
    lines.push(blank());
}

fn auth_budget_lines(budget: &CostBudgetStatus, width: u16) -> Vec<Line<'static>> {
    let pct_style = auth_budget_tone_style(budget.tone);
    let inline = Line::from(vec![
        Span::raw(" "),
        Span::styled(kv_label_col("budget"), theme::muted()),
        Span::styled(budget.cells[0].clone(), theme::primary()),
        Span::styled(" · ", theme::subtle()),
        Span::styled(budget.cells[1].clone(), pct_style),
    ]);
    if inline.width() <= width as usize {
        return vec![inline];
    }
    vec![
        kv_stacked_line(
            &kv("budget", budget.cells[0].clone(), theme::primary()),
            width,
        ),
        Line::from(vec![
            Span::raw(" "),
            Span::raw(" ".repeat(KV_LABEL_WIDTH)),
            Span::styled(fit(&budget.cells[1], kv_value_budget(width)), pct_style),
        ]),
    ]
}

fn auth_budget_tone_style(tone: CostTone) -> ratatui::style::Style {
    match tone {
        CostTone::Success => theme::muted(),
        CostTone::Warn | CostTone::Danger => theme::warn(),
    }
}

fn push_auth_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.extend(command_list_lines(
        &[
            "auth login openai browser",
            "auth login openai headless",
            "auth login anthropic",
            "auth login github-copilot",
            "model <provider:id>",
            "config",
            "back",
        ],
        area.width as usize,
    ));
}
