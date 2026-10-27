use super::*;

pub(super) fn form_lines(app: &ShellApp, form: &LessonForm, area: Rect) -> Vec<Line<'static>> {
    if form.confirming {
        return super::super::shell_view_lines::default_scrolled_lines(
            app,
            area,
            confirmation_document_lines(app, form, area),
        );
    }
    if area.height < 10 {
        return compact_form_lines(app, form, area);
    }
    let mut lines = vec![Line::styled(form_title(form), theme::accent())];
    lines.extend(wrapped("Tab next field · Shift+Tab previous · Shift+Enter newline · Enter inspect · Esc retain draft",area.width,theme::accent()));
    lines.extend(field_summary(form, area.width));
    let names = ["Title", "Lesson text", "Applicability", "Limitations"];
    let label = match form.action {
        LessonFormAction::Draft { .. } => names[form.focused],
        LessonFormAction::Review { .. } => "Review reason (required)",
    };
    lines.push(Line::styled(format!("{label}:"), theme::accent()));
    let notices = notice_lines(app, area.width);
    let height = usize::from(area.height)
        .saturating_sub(lines.len() + notices.len())
        .max(1);
    lines.extend(crate::renderer::shared::field_editor_lines(
        &form.fields[form.focused],
        area.width as usize,
        height,
    ));
    lines.extend(notices);
    lines
}

fn compact_form_lines(app: &ShellApp, form: &LessonForm, area: Rect) -> Vec<Line<'static>> {
    let label = match form.action {
        LessonFormAction::Draft { .. } => {
            ["Title 1/4", "Text 2/4", "Applies 3/4", "Limits 4/4"][form.focused]
        }
        LessonFormAction::Review { .. } => "Review reason",
    };
    let mut lines = vec![Line::styled(format!("LESSON · {label}"), theme::accent())];
    lines.extend(wrapped(
        "Tab field · Enter review · Esc back",
        area.width,
        theme::accent(),
    ));
    let notices = notice_lines(app, area.width)
        .into_iter()
        .take(1)
        .collect::<Vec<_>>();
    let height = usize::from(area.height)
        .saturating_sub(lines.len() + notices.len())
        .max(1);
    lines.extend(crate::renderer::shared::field_editor_lines(
        &form.fields[form.focused],
        area.width as usize,
        height,
    ));
    lines.extend(notices);
    lines
}

fn field_summary(form: &LessonForm, width: u16) -> Vec<Line<'static>> {
    match &form.action {
        LessonFormAction::Draft {
            finding_id,
            reference,
        } => wrapped(
            &format!(
                "Origin: {} · edits require new acceptance",
                reference
                    .as_ref()
                    .map(|reference| format!("{} v{}", reference.lesson_id, reference.revision))
                    .unwrap_or_else(|| format!("generation #{}", finding_id.unwrap_or_default()))
            ),
            width,
            theme::muted(),
        ),
        LessonFormAction::Review { record, .. } => wrapped(
            &format!(
                "{} · v{} · origin generation #{}",
                safe(&record.content.title),
                record.revision,
                record.origin.finding.finding_id
            ),
            width,
            theme::primary(),
        ),
    }
}

pub(super) fn confirmation_document_lines(
    app: &ShellApp,
    form: &LessonForm,
    area: Rect,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        format!("CONFIRM {}", form_title(form)),
        theme::accent(),
    )];
    lines.extend(field_summary(form, area.width));
    lines.extend(wrapped(
        "Enter records this action · Esc edits · PgUp/PgDn inspect · Home/End first/last",
        area.width,
        theme::accent(),
    ));
    match &form.action {
        LessonFormAction::Draft { .. } => {
            lines.extend(draft_confirmation_lines(form, area.width));
        }
        LessonFormAction::Review { record, .. } => {
            lines.extend(detail_lines(record, area.width));
            lines.extend(wrapped(
                &format!("Your reason: {}", safe(form.fields[0].text())),
                area.width,
                theme::primary(),
            ));
        }
    }
    lines.extend(wrapped("This action does not start scans or change finding verdicts. Context reuse is a separate explicit action.",area.width,theme::muted()));
    lines.extend(notice_lines(app, area.width));
    lines
}

fn draft_confirmation_lines(form: &LessonForm, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (label, field) in ["Title", "Lesson", "Applies", "Limits"]
        .iter()
        .zip(&form.fields)
    {
        lines.extend(wrapped(
            &format!("{label}: {}", safe(field.text())),
            width,
            theme::primary(),
        ));
    }
    lines
}

pub(super) fn form_title(form: &LessonForm) -> String {
    match &form.action {
        LessonFormAction::Draft { .. } => "LESSON DRAFT".into(),
        LessonFormAction::Review { state, .. } => format!("{:?} LESSON", state).to_uppercase(),
    }
}
