//! Compact scope disclosure over the shared authenticated query receipt.
use crate::ShellApp;
use kuzushi_core::{findings::FindingScopeFilterReceipt, FindingListFilter};

pub(crate) fn display(app: &ShellApp) -> Option<String> {
    let expression = app.active_findings_filter().as_deref()?;
    let Some(receipt) = app
        .domain()
        .findings_page()
        .and_then(|page| page.scope_filter.as_ref())
    else {
        return Some(expression.into());
    };
    label(expression, receipt).or_else(|| Some(expression.into()))
}

fn label(expression: &str, receipt: &FindingScopeFilterReceipt) -> Option<String> {
    let filter = FindingListFilter::from_filter_expression(expression).ok()?;
    if !filter.has_scope_filter() {
        return None;
    }
    let mut remaining = filter.clone();
    remaining.scope_id.clear();
    remaining.scope_record.clear();
    remaining.limit = FindingListFilter::default().limit;
    if remaining != FindingListFilter::default() {
        return Some(combined_label(expression, receipt));
    }
    let scope = if filter.scope_id.is_empty() {
        "boundaries".into()
    } else {
        filter.scope_id.join(", ")
    };
    let revision = if filter.scope_record.is_empty() {
        "all revisions"
    } else {
        "exact record"
    };
    if !receipt.unavailable_runs.is_empty() {
        return Some(format!(
            "partial scope {scope} · {} unread · {} runs",
            receipt.unavailable_runs.len(),
            receipt.matched_runs
        ));
    }
    Some(format!(
        "scope {scope} · {revision} · {} runs",
        receipt.matched_runs
    ))
}

fn combined_label(expression: &str, receipt: &FindingScopeFilterReceipt) -> String {
    if receipt.unavailable_runs.is_empty() {
        return expression.into();
    }
    format!(
        "partial · {} unread · {expression}",
        receipt.unavailable_runs.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_labels_disclose_historical_or_exact_selection_and_prioritize_missing_metadata() {
        let mut receipt = FindingScopeFilterReceipt {
            matched_runs: 3,
            ..Default::default()
        };
        assert_eq!(
            label("scope:app", &receipt).unwrap(),
            "scope app · all revisions · 3 runs"
        );
        let exact = format!("scope:app scope-record:{}", "a".repeat(64));
        assert_eq!(
            label(&exact, &receipt).unwrap(),
            "scope app · exact record · 3 runs"
        );
        receipt.unavailable_runs.push("missing".into());
        assert_eq!(
            label(&exact, &receipt).unwrap(),
            "partial scope app · 1 unread · 3 runs"
        );
        assert!(label("rank:high", &receipt).is_none());
        assert_eq!(
            label("scope:app sha:aaaa", &receipt).unwrap(),
            "partial · 1 unread · scope:app sha:aaaa"
        );
    }
}
