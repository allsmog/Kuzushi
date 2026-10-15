pub(in crate::renderer) use super::*;
use crate::ui_view_models::prompt_model;

pub(crate) fn render_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    if let Some(line) = inactive_prompt_line(app, area.width) {
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    let prompt = prompt_model(app);
    let segments = prompt_segments(
        &prompt.prefix,
        &prompt.input,
        prompt.cursor,
        area.width as usize,
        " ",
    );
    let completion_hint = app.completion_preview_ref();
    let hint = prompt
        .placeholder
        .as_deref()
        .or(completion_hint.as_deref())
        .unwrap_or_default();
    let line = Line::from(vec![
        // Workbench prefixes carry the selected phase accent; other routes
        // retain the quiet shell prefix so the cursor stays the focal point.
        Span::styled(segments.prompt, prompt_prefix_style(prompt.workbench_mode)),
        Span::raw(segments.before_cursor),
        Span::styled(segments.cursor_text, theme::cursor_block()),
        Span::raw(segments.after_cursor),
        Span::styled(hint, theme::subtle()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn inactive_prompt_line(app: &ShellApp, width: u16) -> Option<Line<'static>> {
    if let Some(text) = captured_surface_prompt(app, width) {
        return Some(disabled_prompt_line(text));
    }
    if app.is_picker_view() {
        return (!app.picker_prompt_focused())
            .then(|| disabled_prompt_line(picker_prompt_hint(width)));
    }
    (app.input_mode() == crate::InputMode::Navigate).then(|| navigation_prompt_line(app))
}

fn captured_surface_prompt(app: &ShellApp, width: u16) -> Option<&'static str> {
    if app.budget_halt_owns_input() {
        return Some("Spending halted · Esc to inspect");
    }
    tool_settings_prompt(app)
        .or_else(|| captured_overlay_prompt(app.shell_view()))
        .or_else(|| relationship_prompt(app))
        .or_else(|| lesson_prompt(app))
        .or_else(|| setup_prompt(app, width))
        .or_else(|| captured_field_prompt(app))
}

fn tool_settings_prompt(app: &ShellApp) -> Option<&'static str> {
    if app.tool_option_editor_open() {
        return Some("Enter saves · Esc keeps draft");
    }
    if app.tools_support_owns_input() {
        return Some("Esc prompt · Enter settings · ↑/↓ tool");
    }
    if support_options_reading(app) {
        return Some("Esc tools · Enter edit · ↑/↓ settings");
    }
    None
}

fn support_options_reading(app: &ShellApp) -> bool {
    app.shell_view() == crate::ShellView::Options
        && app.input_mode() == crate::InputMode::Navigate
        && app.router.options_browser().support_origin.is_some()
        && app.router.options_browser().edit.is_none()
}

fn setup_prompt(app: &ShellApp, width: u16) -> Option<&'static str> {
    if app.shell_view() != crate::ShellView::Setup {
        return None;
    }
    match app.router.setup().editor() {
        Some(crate::app::SetupEditor::Details) => Some("PgUp/PgDn read · Tab/Esc Setup"),
        None if !app.picker_prompt_focused() => Some(setup_overview_prompt(width)),
        _ => None,
    }
}

fn setup_overview_prompt(width: u16) -> &'static str {
    if width < 72 {
        "↑↓ move · Tab details · Enter · type cmd"
    } else {
        "↑/↓ move · Tab details · Enter open/start · type command"
    }
}

fn picker_prompt_hint(width: u16) -> &'static str {
    if width < 72 {
        "↑/↓ move · Enter select · type command"
    } else {
        "type a command · ↑/↓ moves the picker · Enter selects"
    }
}

fn lesson_prompt(app: &ShellApp) -> Option<&'static str> {
    if app.shell_view() != crate::ShellView::Lessons {
        return None;
    }
    (app.router.lessons.form_visible || app.router.lessons.context_selecting)
        .then_some("LESSON REVIEW · Enter inspects or confirms · Esc returns")
}

fn relationship_prompt(app: &ShellApp) -> Option<&'static str> {
    if app.shell_view() != crate::ShellView::Relationships {
        return None;
    }
    if let Some(prompt) = relationship_dialog_prompt(app) {
        return Some(prompt);
    }
    if app.router.relationships.show_groups {
        return group_prompt(app);
    }
    (app.input_mode() == crate::InputMode::Navigate)
        .then_some("RELATIONSHIPS · PgUp/PgDn details · Esc back")
}

fn relationship_dialog_prompt(app: &ShellApp) -> Option<&'static str> {
    if let Some(review) = &app.router.relationships.bulk {
        return Some(match review.stage {
            crate::app::RelationshipBulkStage::Review => {
                "REVIEW SELECTION · j/k pairs · a accept · r separate · u unlink"
            }
            crate::app::RelationshipBulkStage::Reason => {
                "editing reason · Enter reviews confirmation · Esc back"
            }
            crate::app::RelationshipBulkStage::Confirm => {
                "CONFIRM SELECTION · Enter records all · Esc edits reason"
            }
        });
    }
    app.router
        .relationships
        .note
        .as_ref()
        .map(|_| "editing reason · Enter record · Esc cancel")
}

fn group_prompt(app: &ShellApp) -> Option<&'static str> {
    if app.input_mode() != crate::InputMode::Navigate {
        return None;
    }
    if app.router.relationships.groups.request.group_id.is_some() {
        return Some("MEMBERS · Enter finding · Esc group list");
    }
    Some("GROUPS · Enter members · Esc back")
}

#[cfg(test)]
mod tests;

fn captured_field_prompt(app: &ShellApp) -> Option<&'static str> {
    if app.shell_view() == crate::ShellView::Report && app.router.report().editing_path() {
        return Some("editing destination · Enter saves · Esc cancels");
    }
    if app.budget_editor_open() {
        return Some("editing budget · Enter saves · Esc cancels");
    }
    if app.batch_number_editor_open() {
        return Some("editing number · Enter saves · Esc cancels");
    }
    if app.batch_config_open() {
        return Some("↑/↓ choose a setting · Enter edits · L review/launch · Esc back");
    }
    if app.shell_view() == crate::ShellView::FilePicker {
        return Some("type to filter · ↑/↓ select · Enter choose · Esc back");
    }
    captured_map_prompt(app)
}

fn captured_map_prompt(app: &ShellApp) -> Option<&'static str> {
    if app.planning_option_editor_open() {
        return Some("editing option · Shift+Enter new line");
    }
    if app.shell_view() != crate::ShellView::Setup
        || app.router.setup().editor() != Some(crate::app::SetupEditor::ThreatModel)
    {
        return None;
    }
    if app.map_scope_picker_open() {
        return Some("type to filter scopes · ↑/↓ select · Enter choose · Esc cancels");
    }
    let Some(list) = app.router.setup().map_run_config().text() else {
        return Some("↑/↓ choose a setting · Enter edits · Esc returns to Setup");
    };
    map_field_prompt(
        list.field.is_some(),
        list.row == crate::app::MapRunConfigRowId::DesignDocs,
    )
}

fn map_field_prompt(editing: bool, document: bool) -> Option<&'static str> {
    match (editing, document) {
        (true, true) => Some("editing document · Enter saves · Ctrl+O choose a file · Esc cancels"),
        (true, false) => Some("editing context · Enter new line · Ctrl+S saves · Esc cancels"),
        (false, _) => Some("↑/↓ choose an entry · Enter edits · a adds · Esc back"),
    }
}

fn prompt_prefix_style(page: Option<crate::WorkbenchPage>) -> ratatui::style::Style {
    match page {
        Some(crate::WorkbenchPage::Map) => theme::mode_map(),
        Some(crate::WorkbenchPage::Scan) => theme::mode_scan(),
        Some(crate::WorkbenchPage::Review) => theme::mode_review(),
        Some(crate::WorkbenchPage::Prove) => theme::mode_prove(),
        Some(crate::WorkbenchPage::Fix) => theme::mode_fix(),
        None => theme::muted(),
    }
}

fn navigation_prompt_line(app: &ShellApp) -> Line<'static> {
    if crate::ui_view_models::compact_map_reading(app, app.viewport().rows) {
        return Line::styled(
            crate::ui_view_models::navigation_prompt_label(app),
            theme::disabled(),
        );
    }
    if crate::ui_view_models::compact_review_reading(app, app.viewport().rows) {
        return Line::from(vec![
            Span::styled("▣ REVIEW · ", theme::mode_review()),
            Span::styled(
                crate::ui_view_models::navigation_prompt_label(app),
                theme::disabled(),
            ),
        ]);
    }
    if app.shell_view() == crate::ShellView::RunDiff {
        return disabled_prompt_line("SCAN COMPARISON · Tab changes view · Esc back");
    }
    if app.shell_view() == crate::ShellView::Report {
        return disabled_prompt_line("e edits path · Enter exports · Esc returns");
    }
    let Some(page) = crate::ui_view_models::workbench_prompt_mode(app) else {
        return disabled_prompt_line("NAVIGATION MODE — view keys active · Esc returns to prompt");
    };
    Line::from(vec![
        Span::styled(
            crate::ui_view_models::workbench_prompt_token(page),
            prompt_prefix_style(Some(page)),
        ),
        Span::styled(
            crate::ui_view_models::navigation_prompt_label(app),
            theme::disabled(),
        ),
    ])
}

fn captured_overlay_prompt(view: crate::ShellView) -> Option<&'static str> {
    match view {
        crate::ShellView::QuitConfirm => Some("y confirm · n/Esc stay"),
        crate::ShellView::CommandPalette => Some("type to filter · Enter load · Esc close"),
        _ => None,
    }
}

fn disabled_prompt_line(text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, theme::disabled()))
}
