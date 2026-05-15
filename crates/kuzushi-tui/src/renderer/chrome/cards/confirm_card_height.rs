use super::*;
use crate::app::{ConfirmKind, PendingConfirm};
use crate::ui_view_models::threat_patch_card_model;

pub(crate) fn confirm_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    if app.advisory.pending_confirm.is_none() {
        return 0;
    }
    // Header + 3 detail rows (tool, target, rationale/allowlist) + key
    // row.  Up to 6 rows; clamp so very narrow viewports still get a
    // 3-row minimum.
    6.min(area.height.saturating_sub(8) as u16).max(3)
}

pub(crate) fn render_confirm_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(confirm) = app.advisory.pending_confirm.as_ref() else {
        return;
    };
    let width = area.width as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(confirm_header_line(confirm));
    lines.push(confirm_tool_target_line(confirm, width));
    push_optional_confirm_row(
        &mut lines,
        "actor     ",
        confirm.actor.as_deref(),
        width,
        theme::primary(),
    );
    push_optional_confirm_row(
        &mut lines,
        "rationale ",
        confirm.rationale.as_deref(),
        width,
        theme::primary(),
    );
    push_optional_confirm_row(
        &mut lines,
        "allowlist ",
        confirm.allowlist.as_deref(),
        width,
        theme::muted(),
    );
    lines.push(confirm_action_line(confirm));
    render_lines(frame, area, lines);
}

fn confirm_header_line(confirm: &PendingConfirm) -> Line<'static> {
    let (header_glyph, header_style) = confirm_header(confirm.kind);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{header_glyph} "), header_style),
        Span::styled(confirm.kind.label().to_string(), header_style),
    ])
}

fn confirm_header(kind: ConfirmKind) -> (&'static str, Style) {
    match kind {
        ConfirmKind::DestructiveVerb => ("✗", theme::danger()),
        _ => ("⚠", theme::warn()),
    }
}

fn confirm_tool_target_line(confirm: &PendingConfirm, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled("tool      ", theme::muted()),
        Span::styled(confirm.tool.clone(), theme::primary()),
        Span::raw("   "),
        Span::styled("target ", theme::muted()),
        Span::styled(
            fit(&confirm.target, width.saturating_sub(40)),
            theme::primary(),
        ),
    ])
}

fn push_optional_confirm_row(
    lines: &mut Vec<Line<'static>>,
    label: &'static str,
    value: Option<&str>,
    width: usize,
    style: Style,
) {
    if let Some(value) = value {
        lines.push(confirm_detail_line(
            label,
            fit(value, width.saturating_sub(14)),
            style,
        ));
    }
}

fn confirm_detail_line(label: &'static str, value: String, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(label, theme::muted()),
        Span::styled(value, style),
    ])
}

fn confirm_action_line(confirm: &PendingConfirm) -> Line<'static> {
    if confirm.kind.allows_yes() {
        return Line::from(vec![
            Span::raw("  "),
            Span::styled("y", theme::success()),
            Span::raw(" "),
            Span::styled("allow once", theme::muted()),
            Span::raw("   "),
            Span::styled("Y", theme::success()),
            Span::raw(" "),
            Span::styled("allow + remember", theme::muted()),
            Span::raw("   "),
            Span::styled("n", theme::danger()),
            Span::raw(" "),
            Span::styled("deny once", theme::muted()),
            Span::raw("   "),
            Span::styled("N", theme::danger()),
            Span::raw(" "),
            Span::styled("deny + add to denylist", theme::muted()),
        ]);
    }
    Line::from(vec![
        Span::raw("  "),
        Span::styled("rule      ", theme::muted()),
        Span::styled(
            "destructive verb · always refused (no override)".to_string(),
            theme::danger(),
        ),
    ])
}

pub(crate) fn threat_patch_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(patch) = threat_patch_card_model(app) else {
        return 0;
    };
    let body = (patch.unsupported.len() + 1) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}
