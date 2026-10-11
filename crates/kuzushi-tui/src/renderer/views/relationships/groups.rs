use super::*;
use kuzushi_core::findings::{FindingGroupMember, FindingGroupsPage};

pub(super) fn group_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let page = match app.finding_groups_page() {
        ViewDataState::Ready(Ok(page)) => page,
        ViewDataState::Ready(Err(error)) => {
            return wrap_text(
                &format!("Groups unavailable: {error}\nR refreshes the group list."),
                area.width as usize,
            )
            .into_iter()
            .map(|s| Line::styled(s, theme::warn()))
            .collect()
        }
        _ => return vec![Line::raw("Loading recorded finding groups...")],
    };
    let mut lines = group_heading(app, &page, area.width as usize);
    lines.extend(group_rows(app, &page, area));
    lines
}

pub(crate) fn finding_group_page_rows(app: &ShellApp) -> Option<usize> {
    if app.shell_view() == crate::ShellView::Relationships {
        if let Some(review) = &app.router.relationships.bulk {
            return Some(super::bulk::page_rows(app, review));
        }
    }
    if app.shell_view() != crate::ShellView::Relationships || !app.router.relationships.show_groups
    {
        return None;
    }
    let ViewDataState::Ready(Ok(page)) = app.finding_groups_page() else {
        return None;
    };
    let viewport = app.viewport();
    let area = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    Some(
        usize::from(area.height)
            .saturating_sub(group_heading(app, &page, area.width as usize).len())
            .max(1),
    )
}

fn group_heading(app: &ShellApp, page: &FindingGroupsPage, width: usize) -> Vec<Line<'static>> {
    let target = app
        .target()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "selected target".into());
    let label = group_title(app, page);
    let mut lines = wrap_text(&label, width)
        .into_iter()
        .map(|s| Line::styled(s, theme::accent()))
        .collect::<Vec<_>>();
    lines.extend(
        wrap_text(&format!("Target: {target} · {}", scope_label(app)), width)
            .into_iter()
            .map(|s| Line::styled(s, theme::muted())),
    );
    lines.extend(group_range_lines(page, width));
    lines
}

fn scope_label(app: &ShellApp) -> String {
    let request = &app.router.relationships.groups.request;
    let scope = if request.run_ids.is_empty() {
        "all findings".to_string()
    } else {
        format!(
            "observed in {} · latest observations",
            count_label(request.run_ids.len(), "selected run")
        )
    };
    request
        .filter
        .as_deref()
        .map(|filter| format!("{scope} · {}", safe_label(filter)))
        .unwrap_or(scope)
}

fn group_title(app: &ShellApp, page: &FindingGroupsPage) -> String {
    if let Some(group) = &page.selected_group {
        let alias = page
            .members
            .get(app.router.relationships.groups.cursor)
            .map(|member| member.alias.as_str())
            .unwrap_or("none");
        return format!("GROUP MEMBERS · {alias} / {}", group.member_count);
    }
    format!(
        "GROUPED FINDINGS · {} / {}",
        count_label(page.total_groups, "group"),
        count_label(page.total_findings, "finding")
    )
}

fn group_range_lines(page: &FindingGroupsPage, width: usize) -> Vec<Line<'static>> {
    let count = if page.selected_group.is_some() {
        page.total_members
    } else {
        page.total_groups
    };
    let loaded = page.groups.len() + page.members.len();
    wrap_text(
        &format!(
            "Rows {}-{} / {} · recorded ledger {}",
            page.offset + usize::from(loaded > 0),
            page.offset + loaded,
            count,
            page.ledger_watermark
        ),
        width,
    )
    .into_iter()
    .map(Line::raw)
    .collect()
}

fn group_rows(app: &ShellApp, page: &FindingGroupsPage, area: Rect) -> Vec<Line<'static>> {
    let selected = app.router.relationships.groups.cursor;
    let mut lines = Vec::new();
    let count = page.members.len() + page.groups.len();
    let capacity = usize::from(area.height).saturating_sub(8).clamp(1, 7);
    let start = selected
        .saturating_sub(capacity / 2)
        .min(count.saturating_sub(capacity));
    for index in start..count.min(start + capacity) {
        let text = group_row_text(page, index, selected == index);
        lines.extend(wrap_text(&text, area.width as usize).into_iter().map(|s| {
            Line::styled(
                s,
                if selected == index {
                    theme::accent()
                } else {
                    theme::primary()
                },
            )
        }));
    }
    lines.extend(group_detail(page, selected, area.width as usize));
    let available = usize::from(area.height)
        .saturating_sub(group_heading(app, page, area.width as usize).len());
    super::super::shell_view_lines::default_scrolled_lines(
        app,
        Rect {
            height: available as u16,
            ..area
        },
        lines,
    )
}

fn group_row_text(page: &FindingGroupsPage, index: usize, selected: bool) -> String {
    let mark = if selected { "▸" } else { " " };
    if let Some(member) = page.members.get(index) {
        return format!(
            "{mark} {} · {} · {}",
            member.alias,
            member.severity,
            safe_label(&member.title)
        );
    }
    let group = &page.groups[index];
    format!(
        "{mark} {} · {} · {}",
        count_label(group.member_count, "member"),
        group.representative.proof,
        safe_label(&group.representative.title)
    )
}

fn count_label(count: usize, noun: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} {noun}{suffix}")
}

fn group_detail(page: &FindingGroupsPage, selected: usize, width: usize) -> Vec<Line<'static>> {
    let Some(member) = page.members.get(selected) else {
        return group_summary_detail(page, width);
    };
    let text = member_detail(member);
    wrap_text(&text, width).into_iter().map(Line::raw).collect()
}

fn member_detail(member: &FindingGroupMember) -> String {
    let membership = membership_detail(member);
    format!("\n{} · {}\nRecorded decision: {}\nSource: {}\nObservation run: {}{membership}\nEnter opens this observation. Decisions remain independent.",member.alias,member.proof,member.recorded_decision,safe_label(&member.location),safe_label(member.run_id.as_deref().unwrap_or("not recorded")))
}

fn membership_detail(member: &FindingGroupMember) -> String {
    if member.matching_run_ids.is_empty() {
        return String::new();
    }
    let runs = member
        .matching_run_ids
        .iter()
        .map(|run| safe_label(run))
        .collect::<Vec<_>>()
        .join(", ");
    format!("\nObserved in selected runs: {runs}\nRun selection filters history; the displayed observation uses the current ledger. Compare source revisions before carrying a verdict forward.")
}

fn safe_label(value: &str) -> String {
    kuzushi_core::run_lifecycle::SafeText::operator_visible(value).to_string()
}

fn group_summary_detail(page: &FindingGroupsPage, width: usize) -> Vec<Line<'static>> {
    let diagnostics = &page.diagnostics;
    let text = format!("\nAccepted duplicate links group exact recorded observations. Grouping does not complete Review.\n{} inactive duplicate links; {} variant links; {} uncertain links remain separate.\nEnter members · Tab relationships",diagnostics.inactive_duplicate_links,diagnostics.related_variant_links,diagnostics.uncertain_links);
    wrap_text(&text, width).into_iter().map(Line::raw).collect()
}
