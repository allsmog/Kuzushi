use super::*;
use crate::app::{RelationshipBulkReview, RelationshipBulkStage};

pub(super) fn bulk_lines(
    app: &ShellApp,
    review: &RelationshipBulkReview,
    area: Rect,
) -> Vec<Line<'static>> {
    let mut lines = heading(review, area.width as usize);
    let body = Rect {
        height: area.height.saturating_sub(lines.len() as u16),
        ..area
    };
    let detail = match review.stage {
        RelationshipBulkStage::Review => review_detail(app, review, body.width as usize),
        RelationshipBulkStage::Reason => reason_lines(app, review, body),
        RelationshipBulkStage::Confirm => confirmation_lines(app, review, body.width as usize),
    };
    if review.stage == RelationshipBulkStage::Reason {
        lines.extend(detail);
    } else {
        lines.extend(super::super::shell_view_lines::default_scrolled_lines(
            app, body, detail,
        ));
    }
    lines
}

fn heading(review: &RelationshipBulkReview, width: usize) -> Vec<Line<'static>> {
    let label = match review.stage {
        RelationshipBulkStage::Review => format!(
            "REVIEW {} RELATIONSHIPS · {}/{}",
            review.records.len(),
            review.cursor + 1,
            review.records.len()
        ),
        RelationshipBulkStage::Reason => format!(
            "{} {} relationships · reason",
            relationship_action_label(review.state),
            review.records.len()
        ),
        RelationshipBulkStage::Confirm => format!(
            "CONFIRM {} {} relationships · 0 model calls",
            relationship_action_label(review.state),
            review.records.len()
        ),
    };
    wrap_text(&label, width)
        .into_iter()
        .map(|line| Line::styled(line, theme::accent()))
        .collect()
}

fn review_detail(
    app: &ShellApp,
    review: &RelationshipBulkReview,
    width: usize,
) -> Vec<Line<'static>> {
    let row = &review.records[review.cursor];
    let mut lines = source_claim_lines(app, review, width);
    lines.extend(wrap_text(&format!("Target: {}\n{} / {}\n{:?} · {:?}\nThis selection contains {} captured relationship revisions. j/k inspects each pair. No finding verdict changes.",safe(&review.target.display().to_string()),endpoint_label(app,&row.from),endpoint_label(app,&row.to),row.kind,row.state,review.records.len()),width).into_iter().map(Line::raw));
    lines.extend(detail_lines(row, width));
    lines.extend(batch_notice(app, width));
    lines
}

fn source_claim_lines(
    app: &ShellApp,
    review: &RelationshipBulkReview,
    width: usize,
) -> Vec<Line<'static>> {
    let record = &review.records[review.cursor];
    let endpoint = if review.inspecting_destination {
        &record.to
    } else {
        &record.from
    };
    let heading = format!(
        "Inspecting {} · [/] chooses source · Enter opens it",
        if review.inspecting_destination {
            "destination"
        } else {
            "origin"
        },
    );
    let claim = cached_claim(app, endpoint.finding_id);
    wrap_text(&format!("{claim}\n{heading}"), width)
        .into_iter()
        .map(Line::raw)
        .collect()
}

fn cached_claim(app: &ShellApp, finding_id: i64) -> String {
    app.findings()
        .iter()
        .find(|finding| finding.id == Some(finding_id))
        .map(|finding| {
            format!(
                "{}\n{}:{} · {}",
                safe(&finding.title),
                safe(&finding.file_path),
                finding.start_line,
                finding.severity.as_str()
            )
        })
        .unwrap_or_else(|| {
            "Claim is outside the loaded finding page. Enter reads its recorded generation.".into()
        })
}

fn reason_lines(app: &ShellApp, review: &RelationshipBulkReview, area: Rect) -> Vec<Line<'static>> {
    let notices = batch_notice(app, area.width as usize);
    let mut lines = vec![Line::raw("Reason (required):")];
    let height = usize::from(area.height)
        .saturating_sub(1 + notices.len())
        .max(1);
    lines.extend(crate::renderer::shared::field_editor_lines(
        &review.field,
        area.width as usize,
        height,
    ));
    lines.extend(notices);
    lines
}

fn confirmation_lines(
    app: &ShellApp,
    review: &RelationshipBulkReview,
    width: usize,
) -> Vec<Line<'static>> {
    let target = review
        .target
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let mut text = format!("Target: {}\nRecord {:?} for exactly {} relationships in one atomic write. Findings, verdicts and observations stay independent.\nReason: {}\nCaptured selection:",safe(&target),review.state,review.records.len(),safe_multiline(review.field.text()));
    for record in &review.records {
        text.push_str(&format!(
            "\n{} / {} · {:?} · revision {}\n{}",
            endpoint_label(app, &record.from),
            endpoint_label(app, &record.to),
            record.kind,
            record.revision,
            record.id
        ));
    }
    text.push_str(&format!(
        "\nFull target path: {}",
        safe(&review.target.display().to_string())
    ));
    let mut lines = wrap_text(&text, width)
        .into_iter()
        .map(Line::raw)
        .collect::<Vec<_>>();
    lines.extend(batch_notice(app, width));
    lines
}

fn batch_notice(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    app.router
        .relationships
        .notice
        .as_deref()
        .map(|notice| {
            wrap_text(notice, width)
                .into_iter()
                .map(|line| Line::styled(line, theme::warn()))
                .collect()
        })
        .unwrap_or_default()
}

fn safe(value: &str) -> String {
    kuzushi_core::run_lifecycle::SafeText::operator_visible(value).to_string()
}

fn safe_multiline(value: &str) -> String {
    value.split('\n').map(safe).collect::<Vec<_>>().join("\n")
}

pub(super) fn page_rows(app: &ShellApp, review: &RelationshipBulkReview) -> usize {
    let viewport = app.viewport();
    let area = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    usize::from(area.height)
        .saturating_sub(heading(review, area.width as usize).len())
        .max(1)
}
