use crate::renderer::shared::text::wrap_text;
use crate::{ConfirmKind, PendingConfirm, ShellApp};

/// The same wrapped document and page extent drive rendering and approval.
pub(crate) struct AllowanceReviewModel {
    pub title: &'static str,
    pub lines: Vec<String>,
    pub offset: usize,
    pub page_rows: usize,
    pub max_offset: usize,
}

impl AllowanceReviewModel {
    pub(crate) fn allows_approval(&self) -> bool {
        self.page_rows > 0 && self.offset == self.max_offset
    }

    pub(crate) fn position(&self) -> String {
        format!(
            "{}–{} of {}",
            self.offset + 1,
            (self.offset + self.page_rows).min(self.lines.len()),
            self.lines.len()
        )
    }
}

pub(crate) fn allowance_review_width(columns: u16) -> u16 {
    columns.min(104)
}

pub(crate) fn allowance_review_model(
    app: &ShellApp,
    columns: u16,
    rows: u16,
) -> Option<AllowanceReviewModel> {
    let confirm = app.advisory().pending_confirm.as_ref()?;
    let title = review_title(confirm.kind)?;
    let width = usize::from(allowance_review_width(columns).saturating_sub(4)).max(1);
    let lines = document(confirm)
        .into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect::<Vec<_>>();
    let page_rows = usize::from(rows.saturating_sub(6));
    let max_offset = lines.len().saturating_sub(page_rows);
    Some(AllowanceReviewModel {
        title,
        lines,
        offset: app.advisory().confirm_scroll.min(max_offset),
        page_rows,
        max_offset,
    })
}

fn review_title(kind: ConfirmKind) -> Option<&'static str> {
    match kind {
        ConfirmKind::InvestigationAllowance => Some("REVIEW ALLOWANCE"),
        ConfirmKind::InvestigationWork => Some("REVIEW PLAN & ALLOWANCE"),
        _ => None,
    }
}

fn document(confirm: &PendingConfirm) -> Vec<String> {
    let mut lines = vec![confirm.target.clone(), String::new()];
    lines.extend(
        confirm
            .rationale
            .as_deref()
            .unwrap_or("Terms unavailable")
            .lines()
            .map(str::to_owned),
    );
    lines
}

#[cfg(test)]
mod tests;
