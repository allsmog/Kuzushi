use super::*;
use crate::ui_view_models::{
    plain_command_result_model, plain_live_activity_model, plain_prereq_plan_model,
    plain_render_mode, plain_run_projection_model, retry_card_model, PlainCommandResultModel,
    PlainInteractiveOnlyModel, PlainLiveActivityModel, PlainPrereqPlanModel, PlainRenderMode,
    PlainRunProjectionModel, RetryCardModel,
};

pub fn render_plain_app(app: &ShellApp, width: usize) -> String {
    let lines = render_plain_lines(app, width);
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

pub fn render_plain_command_result(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> String {
    let lines = render_plain_command_result_lines(app, width, command, log_start);
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

pub(crate) fn render_plain_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let width = width.max(40);
    if let Some(lines) = plain_overlay_lines(app, width) {
        return lines;
    }
    let mode = plain_render_mode(app);
    let include_run_projection = !matches!(&mode, PlainRenderMode::Activity);
    let mut lines = match mode {
        PlainRenderMode::Activity => plain_line_based_view_lines(app, width, false),
        PlainRenderMode::RunDiff => plain_run_diff_lines(app, width),
        PlainRenderMode::Options(view) => plain_options_lines(app, width, view),
        PlainRenderMode::SastTasks => plain_sast_tasks_lines(app, width),
        PlainRenderMode::Context => plain_context_lines(app, width),
        PlainRenderMode::ProjectModel => plain_project_model_lines(app, width),
        PlainRenderMode::StrategyQueue => plain_strategy_queue_lines(app, width),
        PlainRenderMode::Workspace => plain_workspace_lines(app, width),
        PlainRenderMode::KnowledgeBase => plain_knowledge_base_lines(app, width),
        PlainRenderMode::Config => plain_config_lines(app, width),
        PlainRenderMode::Help => plain_help_lines(app, width),
        PlainRenderMode::InteractiveOnly(model) => interactive_only_plain_lines(app, width, model),
        PlainRenderMode::LineBased {
            include_context_strip,
        } => plain_line_based_view_lines(app, width, include_context_strip),
    };

    lines.extend(crate::renderer::answer_plain_lines(app, width));
    lines = prepend_plain_activity_lines(app, width, include_run_projection, lines);

    lines = finalize_width_safe_plain_lines(lines, width);
    trim_plain_lines(lines)
}

fn plain_overlay_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if let Some(lines) = goal_or_source_overlay(app) {
        return Some(lines);
    }
    if let Some(lines) = primary_overlay_lines(app, width) {
        return Some(lines);
    }
    app.brief_editor()
        .map(|editor| {
            let mut lines = crate::ui_view_models::study_config::brief::plain_lines(editor, width);
            if let Some(note) = app.study_checkpoint_note() {
                lines.insert(1, note);
            }
            lines
        })
        .or_else(|| context_edit_overlay_lines(app, width))
}

fn primary_overlay_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    crate::renderer::allowance_review::allowance_review_plain_lines(app, width)
        .or_else(|| review_plain_overlay_lines(app, width))
        .or_else(|| super::super::scope_review::scope_review_plain_lines(app, width))
        .or_else(|| crate::ui_view_models::context_history::history_plain_lines(app, width))
        .or_else(|| crate::ui_view_models::study_config::recovery::plain_lines(app, width))
        .or_else(|| case_name_overlay_lines(app, width))
}

fn case_name_overlay_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if !app.batch_config_open() || app.advisory().pending_confirm.is_some() {
        return None;
    }
    let config = app.router.campaign().batch_scan_config.as_ref()?;
    let mut lines = crate::ui_view_models::case_name_plain_lines(config, width)?;
    if let Some(note) = app.study_checkpoint_note() {
        lines.insert(1, note);
    }
    Some(lines)
}

fn review_plain_overlay_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if !app.review_study_is_open() || app.advisory().pending_confirm.is_some() {
        return None;
    }
    let config = crate::ui_view_models::study_config::study_projection(app)?;
    let mut lines = crate::ui_view_models::review_study::review_study_lines(
        &config,
        app.config().model.as_deref(),
        width,
    );
    if let Some(edit) = &config.number_edit {
        lines.insert(
            0,
            format!(
                "Editing {}: {} · Enter saves · Esc cancels",
                edit.row.label(),
                edit.field.text()
            ),
        );
    }
    lines.extend(
        crate::ui_view_models::review_study::review_controls()
            .lines()
            .map(str::to_owned),
    );
    Some(lines)
}

fn context_edit_overlay_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if !app.batch_config_open() || app.advisory().pending_confirm.is_some() {
        return None;
    }
    let draft = app.context_edit_draft()?;
    Some(
        crate::ui_view_models::context_edit::context_edit_plain_lines(
            draft,
            width,
            app.context_checkpoint_note(),
        ),
    )
}

fn interactive_only_plain_lines(
    app: &ShellApp,
    width: usize,
    model: PlainInteractiveOnlyModel,
) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.push(model.next);
    lines
}

fn plain_line_based_view_lines(
    app: &ShellApp,
    width: usize,
    include_context_strip: bool,
) -> Vec<String> {
    let area = Rect::new(0, 0, width.min(u16::MAX as usize) as u16, u16::MAX);
    let body = shell_view_lines(app, area)
        .into_iter()
        .map(line_to_unstyled_text)
        .collect::<Vec<_>>();
    if !include_context_strip {
        return body;
    }

    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.extend(body);
    lines
}

fn plain_run_diff_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let area = Rect::new(0, 0, width.min(u16::MAX as usize) as u16, u16::MAX);
    crate::renderer::run_diff_document_lines(app, area)
        .into_iter()
        .map(line_to_unstyled_text)
        .collect()
}

pub(crate) fn render_plain_command_result_lines(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> Vec<String> {
    let width = width.max(40);
    let model = plain_command_result_model(app, command, log_start);
    let mut lines = plain_command_result_lines(model, width);
    lines.push(String::new());
    lines.extend(render_plain_lines(app, width));

    let lines = finalize_width_safe_plain_lines(lines, width);
    trim_plain_lines(lines)
}

fn plain_command_result_lines(model: PlainCommandResultModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider(model.result_title, width)];
    lines.extend(model.rows);
    lines.push(String::new());
    lines.push(plain_section_divider(model.view_title, width));
    lines
}

fn plain_prereq_plan_lines(plan: PlainPrereqPlanModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider(plan.title, width)];
    lines.extend(plan.rows);
    lines
}

fn prepend_plain_activity_lines(
    app: &ShellApp,
    width: usize,
    include_run_projection: bool,
    lines: Vec<String>,
) -> Vec<String> {
    let prefix = plain_activity_prefix(app, width, include_run_projection);
    if prefix.is_empty() {
        return lines;
    }
    prefix.into_iter().chain(lines).collect()
}

fn plain_activity_prefix(
    app: &ShellApp,
    width: usize,
    include_run_projection: bool,
) -> Vec<String> {
    [
        optional_plain_retry_lines(app, width),
        optional_plain_run_lines(app, width, include_run_projection),
        optional_plain_prereq_lines(app, width),
    ]
    .concat()
}

fn optional_plain_retry_lines(app: &ShellApp, width: usize) -> Vec<String> {
    retry_card_model(app)
        .map(|model| with_trailing_blank(plain_retry_card_lines(model, width)))
        .unwrap_or_default()
}

fn optional_plain_run_lines(
    app: &ShellApp,
    width: usize,
    include_run_projection: bool,
) -> Vec<String> {
    if !include_run_projection {
        return Vec::new();
    }
    if let Some(model) = plain_run_projection_model(app) {
        return with_trailing_blank(plain_run_projection_lines(model, width));
    }
    plain_live_activity_model(app)
        .map(|model| with_trailing_blank(plain_live_activity_lines(model, width)))
        .unwrap_or_default()
}

fn optional_plain_prereq_lines(app: &ShellApp, width: usize) -> Vec<String> {
    plain_prereq_plan_model(app)
        .map(|model| with_trailing_blank(plain_prereq_plan_lines(model, width)))
        .unwrap_or_default()
}

fn with_trailing_blank(mut lines: Vec<String>) -> Vec<String> {
    lines.push(String::new());
    lines
}

fn plain_run_projection_lines(model: PlainRunProjectionModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider(model.title, width)];
    lines.extend(model.rows.into_iter().map(|row| {
        let _source_key = row.key;
        row.text
    }));
    lines
}

fn plain_retry_card_lines(model: RetryCardModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider("RETRY", width)];
    lines.push(format!(
        "{} task(s) failed. y/Enter retry; n/Esc skip.",
        model.failed_count
    ));
    lines.extend(
        model
            .rows
            .into_iter()
            .map(|row| format!("- {}: {}", row.tool, row.error)),
    );
    lines
}

fn plain_live_activity_lines(model: PlainLiveActivityModel, width: usize) -> Vec<String> {
    let mut lines = vec![plain_section_divider(model.title, width)];
    lines.extend(model.rows);
    lines
}

fn goal_or_source_overlay(app: &ShellApp) -> Option<Vec<String>> {
    if let Some(state) = app.goal_review() {
        return Some(crate::ui_view_models::goal_review::plain_lines(state));
    }
    app.source_review_form()
        .map(crate::ui_view_models::source_review::source_review_plain_lines)
}
