//! The interactive projection and exhaustive plain reader share the same stored comparison.
use super::context_wrap;
use crate::app::{ContextComparisonView, StudyContextComparison};
use kuzushi_core::capabilities::threat_model::{
    ContextCollectionOrderDifference, ContextDifferenceSection, ContextSourceClaims,
    ContextTextDifference, ContextValueDifference,
};
use ratatui::layout::{Margin, Rect};
mod content;

pub(crate) enum ComparisonEntry<'a> {
    Text(&'a ContextTextDifference),
    Field(&'a ContextValueDifference),
    Order(&'a ContextCollectionOrderDifference),
    Source(&'a ContextSourceClaims),
}

pub(crate) struct ComparisonLayout {
    pub tabs: Rect,
    pub list: Rect,
    pub detail: Rect,
    pub controls: Rect,
}

pub(crate) fn layout(area: Rect) -> ComparisonLayout {
    let inner = area.inner(Margin::new(2, 1));
    let tabs = Rect::new(inner.x, inner.y, inner.width, inner.height.min(1));
    let controls = Rect::new(
        inner.x,
        inner.bottom().saturating_sub(2),
        inner.width,
        inner.height.min(2),
    );
    let body = Rect::new(
        inner.x,
        tabs.bottom(),
        inner.width,
        controls.y.saturating_sub(tabs.bottom()),
    );
    let (list, detail) = content_areas(body);
    ComparisonLayout {
        tabs,
        list,
        detail,
        controls,
    }
}

fn content_areas(body: Rect) -> (Rect, Rect) {
    if body.width >= 96 && body.height >= 15 {
        let width = (body.width / 3).min(38);
        return (
            Rect::new(body.x, body.y, width, body.height),
            Rect::new(
                body.x + width + 2,
                body.y,
                body.width.saturating_sub(width + 2),
                body.height,
            ),
        );
    }
    let list_height = if body.height >= 12 { 3 } else { 1 }.min(body.height);
    (
        Rect::new(body.x, body.y, body.width, list_height),
        Rect::new(
            body.x,
            body.y + list_height,
            body.width,
            body.height.saturating_sub(list_height),
        ),
    )
}

pub(crate) fn label(view: ContextComparisonView) -> &'static str {
    match view {
        ContextComparisonView::Text => "Text",
        ContextComparisonView::Structure => "Graph",
        ContextComparisonView::Source => "Source",
        ContextComparisonView::Other => "Other",
    }
}

pub(crate) fn entries(
    context: &StudyContextComparison,
    view: ContextComparisonView,
) -> Vec<ComparisonEntry<'_>> {
    if !context.ready() {
        return Vec::new();
    }
    if view == ContextComparisonView::Text {
        return context
            .differences
            .iter()
            .flatten()
            .map(ComparisonEntry::Text)
            .collect();
    }
    context
        .structure
        .as_ref()
        .map_or_else(Vec::new, |structure| structure_entries(structure, view))
}

fn structure_entries(
    structure: &kuzushi_core::capabilities::threat_model::ContextDocumentDiff,
    view: ContextComparisonView,
) -> Vec<ComparisonEntry<'_>> {
    let mut entries = Vec::new();
    if view == ContextComparisonView::Source {
        entries.push(ComparisonEntry::Source(&structure.source_claims));
    }
    entries.extend(
        structure
            .changes
            .iter()
            .filter(|change| includes(view, change.section))
            .map(ComparisonEntry::Field),
    );
    if view == ContextComparisonView::Other {
        entries.extend(
            structure
                .reordered_collections
                .iter()
                .map(ComparisonEntry::Order),
        );
    }
    entries
}

fn includes(view: ContextComparisonView, section: ContextDifferenceSection) -> bool {
    match view {
        ContextComparisonView::Structure => matches!(
            section,
            ContextDifferenceSection::Architecture
                | ContextDifferenceSection::SecurityContext
                | ContextDifferenceSection::Questions
        ),
        ContextComparisonView::Source => section == ContextDifferenceSection::Inputs,
        ContextComparisonView::Other => section == ContextDifferenceSection::Other,
        ContextComparisonView::Text => false,
    }
}

pub(crate) fn title(entry: &ComparisonEntry<'_>) -> String {
    match entry {
        ComparisonEntry::Text(change) => change.label.clone(),
        ComparisonEntry::Field(change) => content::field_title(change),
        ComparisonEntry::Order(change) => format!("Order: {}", change.collection),
        ComparisonEntry::Source(_) => "Saved source and context identities".into(),
    }
}

pub(crate) fn selected_lines(context: &StudyContextComparison, width: usize) -> Vec<String> {
    let entries = entries(context, context.view);
    let selected = context
        .cursor()
        .selected
        .min(entries.len().saturating_sub(1));
    let lines = entries
        .get(selected)
        .map_or_else(|| status(context), |entry| content::lines(context, entry));
    wrap(lines, width)
}

pub(crate) fn all_lines(context: &StudyContextComparison, width: usize) -> Vec<String> {
    let mut lines =
        vec!["COMPARE SAVED CONTEXT · No model request. Selection changes this study only.".into()];
    if !context.ready() {
        lines.extend(status(context));
        return wrap(lines, width);
    }
    for view in ContextComparisonView::ALL {
        lines.push(format!("VIEW: {}", label(view)));
        for entry in entries(context, view) {
            lines.extend(content::lines(context, &entry));
        }
    }
    wrap(lines, width)
}

fn status(context: &StudyContextComparison) -> Vec<String> {
    if let Some(error) = &context.error {
        return vec![format!("Parent unavailable: {error}"), "Enter retries the exact local parent read. No model request. Esc returns to the candidate.".into()];
    }
    if !context.ready() {
        return vec!["Reading the authenticated parent. No model request.".into()];
    }
    vec![format!("No {} changes in these saved revisions.", label(context.view)), "Tab reviews other changes. Source lists exact context identities and recorded source claims.".into()]
}

fn wrap(lines: Vec<String>, width: usize) -> Vec<String> {
    lines
        .into_iter()
        .flat_map(|line| context_wrap(&line, width.max(1)))
        .collect()
}

#[cfg(test)]
mod tests;
