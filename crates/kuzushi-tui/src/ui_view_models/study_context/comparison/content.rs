use super::*;
use kuzushi_core::capabilities::threat_model::{ContextDifferenceMatching, ContextSourceClaims};
use serde_json::{json, Value};

pub(super) fn field_title(change: &ContextValueDifference) -> String {
    let action = match (&change.before, &change.after) {
        (None, _) => "Add",
        (_, None) => "Remove",
        _ => "Change",
    };
    let identity = change
        .identity
        .as_ref()
        .map_or_else(String::new, |id| format!(" {}", json!(id)));
    let subject = format!(
        "{}{identity}",
        collection_label(change.collection.as_deref())
    );
    match change.collection {
        Some(_) if change.field.is_empty() => format!("{action} {subject}"),
        Some(_) => format!("{action} field {} on {subject}", change.field),
        None => format!("{action} field {}", change.field),
    }
}

fn collection_label(collection: Option<&str>) -> &str {
    match collection {
        Some("/dfd/nodes") => "node",
        Some("/dfd/flows") => "flow",
        Some("/dfd/trustBoundaries") => "boundary",
        Some("/openQuestions") => "question",
        Some(path) => path,
        None => "field",
    }
}

pub(super) fn lines(context: &StudyContextComparison, entry: &ComparisonEntry<'_>) -> Vec<String> {
    match entry {
        ComparisonEntry::Text(change) => text_lines(change),
        ComparisonEntry::Field(change) => field_lines(change),
        ComparisonEntry::Order(change) => order_lines(change),
        ComparisonEntry::Source(claims) => source_lines(context, claims),
    }
}

fn text_lines(change: &ContextTextDifference) -> Vec<String> {
    let mut lines = vec![change.label.clone(), "Before:".into()];
    lines.extend(change.before.lines().map(str::to_owned));
    lines.push("After:".into());
    lines.extend(change.after.lines().map(str::to_owned));
    lines.push(format!("Candidate field: {}", change.pointer));
    lines
}

fn field_lines(change: &ContextValueDifference) -> Vec<String> {
    let mut lines = vec![field_title(change), matching_label(change.matching).into()];
    lines.push("Before:".into());
    lines.extend(value_lines(change.before.as_ref()));
    lines.push("After:".into());
    lines.extend(value_lines(change.after.as_ref()));
    lines.push(format!(
        "Parent pointer: {}",
        pointer_label(change.before_pointer.as_deref())
    ));
    lines.push(format!(
        "Candidate pointer: {}",
        pointer_label(change.after_pointer.as_deref())
    ));
    lines
}

fn pointer_label(pointer: Option<&str>) -> String {
    pointer.map_or_else(
        || "(not present)".into(),
        |pointer| json!(pointer).to_string(),
    )
}

fn matching_label(matching: ContextDifferenceMatching) -> &'static str {
    match matching {
        ContextDifferenceMatching::Id => "Matched by exact literal ID.",
        ContextDifferenceMatching::Position => {
            "No unique ID; compared by position. Identity is uncertain."
        }
        ContextDifferenceMatching::AmbiguousPosition => {
            "Duplicate ID; compared by position. Identity is ambiguous."
        }
        ContextDifferenceMatching::DocumentField => "Compared by exact document field.",
    }
}

fn order_lines(change: &ContextCollectionOrderDifference) -> Vec<String> {
    let mut lines = vec![
        format!("Order: {}", change.collection),
        "Same unique IDs; stored order changed. This does not establish semantic equivalence."
            .into(),
        "Before:".into(),
    ];
    lines.extend(value_lines(Some(&json!(change.before))));
    lines.push("After:".into());
    lines.extend(value_lines(Some(&json!(change.after))));
    lines
}

fn source_lines(context: &StudyContextComparison, claims: &ContextSourceClaims) -> Vec<String> {
    let mut lines = vec![
        "SAVED SOURCE AND CONTEXT IDENTITIES".into(),
        source_summary(claims).into(),
    ];
    lines.extend(revision_warning("Parent", &claims.before));
    lines.extend(revision_warning("Candidate", &claims.after));
    lines.extend(["Recorded claims do not check the current checkout or establish finding fixes. Recognized source claims are retained separately.".into(), "Parent context reference:".into()]);
    lines.extend(value_lines(Some(&json!(context.parent))));
    lines.push("Candidate context reference:".into());
    lines.extend(value_lines(Some(&json!(context.candidate))));
    lines.push("Parent source claims:".into());
    lines.extend(claim_lines(&claims.before));
    lines.push("Candidate source claims:".into());
    lines.extend(claim_lines(&claims.after));
    lines
}

fn revision_warning(
    side: &str,
    claims: &std::collections::BTreeMap<String, Value>,
) -> Option<String> {
    let revisions = ["/provenance/revision", "/provenance/gitRevision"]
        .into_iter()
        .filter_map(|key| claims.get(key).and_then(Value::as_str));
    let nested = ["/provenance/targetGit", "/targetGit"]
        .into_iter()
        .filter_map(|key| claims.get(key)?.get("sha")?.as_str());
    let values = revisions
        .chain(nested)
        .collect::<std::collections::BTreeSet<_>>();
    (values.len() > 1).then(|| format!("{side} recorded revision fields disagree. Review every claim; no source identity is selected automatically."))
}

fn source_summary(claims: &ContextSourceClaims) -> &'static str {
    if claims.before.is_empty() || claims.after.is_empty() {
        return "Source claims missing on at least one side; comparison is incomplete.";
    }
    if claims.before != claims.after {
        return "Saved source claims differ. Review SHA, tree, scope and completeness values.";
    }
    "Saved source claims match. This is not a current source check."
}

fn claim_lines(claims: &std::collections::BTreeMap<String, Value>) -> Vec<String> {
    if claims.is_empty() {
        return vec!["(not recorded)".into()];
    }
    value_lines(Some(&json!(claims)))
}

fn value_lines(value: Option<&Value>) -> Vec<String> {
    value.map_or_else(
        || vec!["(not present)".into()],
        |value| {
            serde_json::to_string_pretty(value)
                .expect("JSON values serialize")
                .lines()
                .map(str::to_owned)
                .collect()
        },
    )
}
