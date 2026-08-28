use super::*;
use crate::app::MapRunConfigRowId;

pub(crate) fn map_run_config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let width = area.width as usize;
    let summary = app.map_run_config_summary();
    let mut lines = vec![divider("SETUP · THREAT MODEL", area.width)];
    lines.push(muted(&fit(
        "Configure the descriptor input used by shell, run, and expanded scoped builds.",
        width,
    )));
    lines.push(blank());
    for (index, row) in MapRunConfigRowId::ALL.iter().copied().enumerate() {
        let value = row_value(row, &summary);
        lines.push(selection_band(
            &format!("  {:<14} {value}", row_label(row)),
            index == app.router.setup().map_run_config().cursor(),
            width,
        ));
    }
    lines.extend(editor_lines(app, width));
    lines.push(blank());
    lines.push(muted(&fit(
        &format!(
            " {} build(s) · {} · design docs {} · context rows {}",
            summary.selected_scopes, summary.cost, summary.design_docs, summary.context_rows
        ),
        width,
    )));
    lines.extend(scope_notice_lines(app, &summary, width));
    lines
}

fn row_label(row: MapRunConfigRowId) -> &'static str {
    match row {
        MapRunConfigRowId::Methodology => "Methodology",
        MapRunConfigRowId::Scope => "Scope",
        MapRunConfigRowId::DesignDocs => "Design docs",
        MapRunConfigRowId::Context => "Context",
    }
}

fn row_value(row: MapRunConfigRowId, summary: &crate::app::MapRunConfigSummary) -> String {
    match row {
        MapRunConfigRowId::Methodology => summary.methodology.clone(),
        MapRunConfigRowId::Scope => summary.scope.clone(),
        MapRunConfigRowId::DesignDocs => format!("{} source(s)", summary.design_docs),
        MapRunConfigRowId::Context => format!("{} row(s)", summary.context_rows),
    }
}

fn editor_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let state = app.router.setup().map_run_config();
    let Some(row) = state.edit() else {
        return Vec::new();
    };
    let value = if state.draft().is_empty() {
        "<none>"
    } else {
        state.draft()
    };
    vec![
        blank(),
        styled(
            &fit(&format!(" edit {} · {value}", row_label(row)), width),
            theme::accent(),
        ),
        muted(" comma or newline separates values · Enter saves · Esc cancels"),
    ]
}

fn scope_notice_lines(
    app: &ShellApp,
    summary: &crate::app::MapRunConfigSummary,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if summary.review_required {
        lines.push(styled(
            &fit(
                &format!(
                    " ! {} scopes exceeds the review threshold {} · press Enter on Scope again to confirm",
                    summary.selected_scopes,
                    crate::app::ALL_SCOPES_REVIEW_THRESHOLD
                ),
                width,
            ),
            theme::warn(),
        ));
    }
    if let Some(error) = summary
        .scope_error
        .as_deref()
        .or_else(|| app.router.setup().map_run_config().error())
    {
        lines.push(styled(&fit(&format!(" ! {error}"), width), theme::danger()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{SetupEditor, ShellView};
    use kuzushi_core::V2Config;

    #[test]
    fn threat_model_config_has_tty_and_plain_content_parity() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Setup);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::ThreatModel);
        let area = Rect::new(0, 0, 100, 30);
        let tty = map_run_config_lines(&app, area)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let plain = crate::renderer::render_plain_app(&app, 100);

        for text in [
            "Methodology",
            "Scope",
            "Design docs",
            "Context",
            "upper bound",
        ] {
            assert!(tty.contains(text), "TTY missing {text:?}: {tty}");
            assert!(plain.contains(text), "plain missing {text:?}: {plain}");
        }
    }
}
