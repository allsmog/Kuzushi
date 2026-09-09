use super::super::{
    digest_summary, disposition_summary, provenance_summary, receipt_count_summary,
    responsive_summary, revision_summary, timestamp_summary,
};
use crate::ui_view_models::EntryPointBreakdown;
use ratatui::prelude::Line;

pub(super) fn detail_lines(width: usize, model: &EntryPointBreakdown) -> Vec<Line<'static>> {
    let mut rows = receipt_rows(model);
    rows.extend(
        model
            .receipt
            .warnings
            .iter()
            .map(|warning| format!("WARNING · {warning}")),
    );
    rows.into_iter()
        .flat_map(|text| crate::renderer::shared::text::wrap_text(&text, width))
        .map(|text| Line::styled(text, crate::theme::muted()))
        .collect()
}

fn receipt_rows(model: &EntryPointBreakdown) -> Vec<String> {
    let receipt = &model.receipt;
    vec![
        responsive_summary(usize::MAX, model),
        disposition_summary(usize::MAX, model),
        provenance_summary(usize::MAX, model),
        receipt_count_summary(usize::MAX, model),
        revision_summary(usize::MAX, model),
        digest_summary(usize::MAX, "C SHA256", receipt.catalog_digest.as_deref()),
        digest_summary(
            usize::MAX,
            "M SHA256",
            receipt.model_catalog_digest.as_deref(),
        ),
        digest_pair(
            "CONTEXT",
            receipt.context_digest.as_deref(),
            receipt.model_context_digest.as_deref(),
        ),
        digest_pair(
            "TREE",
            receipt.tree_hash.as_deref(),
            receipt.model_tree_hash.as_deref(),
        ),
        timestamp_summary(usize::MAX, model),
    ]
}

fn digest_pair(label: &str, catalog: Option<&str>, model: Option<&str>) -> String {
    format!(
        "{label} · C {} · M {}",
        catalog.unwrap_or("?"),
        model.unwrap_or("?")
    )
}
