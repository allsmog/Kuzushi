//! Local browser projection. Filtering never changes canonical counts or receipts.
use super::{entry_point_breakdown, EntryPointBreakdown, EntryPointGroup, EntryPointItem};
use crate::ShellApp;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct EntryPointSearchCache {
    source: Arc<EntryPointBreakdown>,
    query: String,
    filtered: Arc<EntryPointBreakdown>,
}

pub(crate) fn entry_point_browser_model(app: &ShellApp) -> Arc<EntryPointBreakdown> {
    let source = entry_point_breakdown(app);
    let query = app.router.scene().entry_point_query().trim();
    if query.is_empty() {
        return source;
    }
    let cached = app
        .workbench_cache()
        .borrow()
        .entry_point_search
        .as_ref()
        .and_then(|cache| {
            (Arc::ptr_eq(&cache.source, &source) && cache.query == query)
                .then(|| Arc::clone(&cache.filtered))
        });
    if let Some(cached) = cached {
        return cached;
    }
    let filtered = Arc::new(filter_entry_points(&source, query));
    app.workbench_cache().borrow_mut().entry_point_search = Some(EntryPointSearchCache {
        source,
        query: query.to_string(),
        filtered: Arc::clone(&filtered),
    });
    filtered
}

fn filter_entry_points(source: &EntryPointBreakdown, query: &str) -> EntryPointBreakdown {
    let terms = query
        .to_lowercase()
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let entries = source
        .entries
        .iter()
        .filter(|entry| entry_matches(entry, &terms))
        .cloned()
        .collect::<Vec<_>>();
    let dispositions = source
        .dispositions
        .iter()
        .filter_map(|group| {
            let count = entries
                .iter()
                .filter(|entry| entry.disposition.label() == group.name)
                .count();
            (count > 0).then(|| EntryPointGroup {
                name: group.name.clone(),
                count,
            })
        })
        .collect();
    EntryPointBreakdown {
        entries,
        dispositions,
        ..source.clone()
    }
}

fn entry_matches(entry: &EntryPointItem, terms: &[String]) -> bool {
    let path = entry.recorded_source().unwrap_or("").to_lowercase();
    let kind = entry.kind.to_lowercase();
    let state = entry.disposition.label().replace(' ', "-");
    let searchable = format!("{} {kind} {path} {state}", entry.name.to_lowercase());
    terms.iter().all(|term| match term.split_once(':') {
        Some(("path", value)) => path.contains(value),
        Some(("kind", value)) => kind.contains(value),
        Some(("state", value)) => state.contains(value),
        _ => searchable.contains(term),
    })
}

pub(crate) fn entry_point_browser_selection(
    app: &ShellApp,
    model: &EntryPointBreakdown,
) -> Option<usize> {
    let route = app.router.scene();
    selected_entry_index(
        model,
        route.entry_point_selected_id(),
        route.entry_point_selection(),
    )
}

fn selected_entry_index(
    model: &EntryPointBreakdown,
    id: Option<&str>,
    index: usize,
) -> Option<usize> {
    if let Some(id) = id {
        return model.entries.iter().position(|entry| entry.id == id);
    }
    (!model.entries.is_empty()).then(|| index.min(model.entries.len() - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::EntryPointDisposition;

    fn entry(id: &str, path: &str) -> EntryPointItem {
        EntryPointItem {
            id: id.into(),
            name: "Parser boundary".into(),
            kind: "parser".into(),
            source: path.into(),
            disposition: EntryPointDisposition::ExtractedOnly,
            trust_zone: String::new(),
            description: String::new(),
            ingress: String::new(),
            evidence: String::new(),
            risk: String::new(),
            disposition_note: String::new(),
            targets: Vec::new(),
            unresolved_target_count: 0,
        }
    }

    #[test]
    fn fielded_search_preserves_ids_and_canonical_evidence_totals() {
        let source = EntryPointBreakdown {
            entries: vec![entry("a", "src/auth.rs:2"), entry("b", "src/net.rs:3")],
            dispositions: vec![EntryPointGroup {
                name: "extracted only".into(),
                count: 2,
            }],
            ..Default::default()
        };
        let filtered = filter_entry_points(&source, "PATH:AUTH kind:parser state:extracted-only");
        assert_eq!(filtered.entries.len(), 1);
        assert_eq!(filtered.entries[0].id, "a");
        assert_eq!(filtered.dispositions[0].count, 1);
        assert_eq!(filtered.counts, source.counts);
        assert_eq!(filtered.receipt, source.receipt);
        assert_eq!(source.entries.len(), 2);
    }

    #[test]
    fn selection_is_identity_bound_when_a_catalog_reorders_or_removes_rows() {
        let source = EntryPointBreakdown {
            entries: vec![entry("b", "src/b.rs:2"), entry("a", "src/a.rs:1")],
            ..Default::default()
        };
        assert_eq!(selected_entry_index(&source, Some("a"), 0), Some(1));
        assert_eq!(selected_entry_index(&source, Some("deleted"), 0), None);
        assert_eq!(
            selected_entry_index(&EntryPointBreakdown::default(), None, 0),
            None
        );
    }

    #[test]
    fn filtering_preserves_an_unreadable_source_explanation() {
        let source = EntryPointBreakdown {
            empty_hint: Some("catalog unreadable".into()),
            ..Default::default()
        };
        assert_eq!(
            filter_entry_points(&source, "anything").empty_hint,
            source.empty_hint
        );
    }

    #[test]
    fn no_matches_is_not_a_claim_that_the_source_catalog_is_empty() {
        let source = EntryPointBreakdown {
            entries: vec![entry("a", "src/a.rs:1")],
            ..Default::default()
        };
        let filtered = filter_entry_points(&source, "nonexistent");
        assert!(filtered.entries.is_empty());
        assert!(filtered.empty_hint.is_none());
        assert_eq!(source.entries.len(), 1);
    }
}
