//! `threat-model:diff`: compare two immutable revisions or lineage heads.

use super::model_commands::workspace_root;
use super::*;

const MAX_THREAT_DETAIL_LINES: usize = 10;
mod context_structure;
mod context_text;

struct RevisionComparison {
    structural: ThreatModelDocumentDiff,
    details: ContextDocumentDiff,
    text: Vec<ContextTextDifference>,
    sections: Vec<String>,
    document_changed: bool,
}

impl RevisionComparison {
    fn new(before: &Value, after: &Value) -> Self {
        Self {
            structural: diff_threat_model_documents(before, after),
            details: context_document_differences(before, after),
            text: context_text_differences(before, after),
            sections: context_text::changed_document_sections(before, after),
            document_changed: before != after,
        }
    }
}

pub(crate) fn diff_threat_model_revisions_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:diff")?;
    let from = load_diff_side(root, &input, "from")?;
    let to = load_diff_side(root, &input, "to")?;
    let comparison = RevisionComparison::new(&from.document, &to.document);
    let mut data = threat_model_diff_data(&from, &to, &comparison)?;
    data["target"] = json!(root);
    Ok(crate::module_result::completed_output_result(
        diff_headline(&comparison),
        render_threat_model_diff(&from, &to, &comparison),
        data,
    ))
}

fn load_diff_side(root: &Path, input: &Value, field: &str) -> Result<ActiveThreatModel> {
    let selector = input
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("{field} is required (a tm_… lineage id or tmr_… revision id)"))?;
    // Fold the whole cause chain into one message: run-mode receipts surface
    // only the outermost error, and the chain names what was tried.
    load_threat_model_by_selector(root, selector).map_err(|error| {
        anyhow::anyhow!("threat-model:diff {field}={selector:?} did not resolve: {error:#}")
    })
}

fn threat_model_diff_data(
    from: &ActiveThreatModel,
    to: &ActiveThreatModel,
    comparison: &RevisionComparison,
) -> Result<Value> {
    let mut data = serde_json::to_value(&comparison.structural)?;
    data["from"] = diff_side_data(from);
    data["to"] = diff_side_data(to);
    data["contextText"] = json!(comparison.text);
    data["contextStructure"] = json!(comparison.details);
    data["changedDocumentSections"] = json!(comparison.sections);
    data["documentChanged"] = json!(comparison.document_changed);
    data["comparisonCoverage"] = json!({
        "contextText":"System overview, component descriptions/purposes and question answers. Unique component/question ids and exact question text match across ordering; unkeyed or ambiguous rows compare by position.",
        "structural":"Selected threat fields, DFD membership, entry-point coverage counts and methodology.",
        "documentSections":"All changed top-level stored sections, including metadata. Section changes do not establish semantic equivalence or finding validity.",
        "contextStructure":"Complete stored values for field changes. Unique collection IDs match literally, duplicate/missing IDs use explicit positional comparison, unique-ID collection order is separate. Other arrays retain their stored order. Recorded source claims do not establish current source or finding verdicts.",
    });
    Ok(data)
}

fn diff_side_data(side: &ActiveThreatModel) -> Value {
    json!({
        "modelId": side.model_ref.model_id,
        "revisionId": side.model_ref.revision_id,
        "sha256": side.model_ref.sha256,
        "methodology": document_methodology(&side.document),
        "threatCount": document_threat_count(&side.document),
    })
}

fn diff_headline(comparison: &RevisionComparison) -> String {
    if !comparison.document_changed && comparison.structural.is_empty() {
        return "threat-model diff: no differences".into();
    }
    format!(
        "threat-model diff: {} context text change(s), {} stored field change(s), {} collection order change(s)",
        comparison.text.len(),
        comparison.details.changes.len(),
        comparison.details.reordered_collections.len()
    )
}

fn render_threat_model_diff(
    from: &ActiveThreatModel,
    to: &ActiveThreatModel,
    comparison: &RevisionComparison,
) -> String {
    let diff = &comparison.structural;
    let mut lines = vec![
        format!(
            "threat-model diff {} -> {}",
            side_label(from),
            side_label(to)
        ),
        format!(
            "stored sections changed: {}",
            context_text::section_labels(&comparison.sections)
        ),
        threat_count_line(from, to, &diff.threats),
        dfd_line(&diff.dfd),
        coverage_line(&diff.coverage),
        methodology_line(from, to, diff.methodology_changed),
    ];
    lines.extend(context_text::render_context_changes(&comparison.text));
    lines.extend(context_structure::render(&comparison.details));
    lines.extend(threat_detail_lines(&diff.threats));
    lines.join("\n")
}

fn side_label(side: &ActiveThreatModel) -> String {
    format!("{}@{}", side.model_ref.model_id, side.model_ref.revision_id)
}

fn threat_count_line(
    from: &ActiveThreatModel,
    to: &ActiveThreatModel,
    threats: &ThreatSetDiff,
) -> String {
    format!(
        "threats: {} -> {} (+{} added, -{} removed, ~{} changed, {} re-keyed, {} unkeyed)",
        document_threat_count(&from.document),
        document_threat_count(&to.document),
        threats.added.len(),
        threats.removed.len(),
        threats.changed.len(),
        threats.rekeyed,
        threats.unkeyed.from + threats.unkeyed.to,
    )
}

fn dfd_line(dfd: &DfdElementDiff) -> String {
    format!(
        "dfd: nodes +{}/-{}, flows +{}/-{}, boundaries +{}/-{}",
        dfd.nodes_added.len(),
        dfd.nodes_removed.len(),
        dfd.flows_added.len(),
        dfd.flows_removed.len(),
        dfd.boundaries_added.len(),
        dfd.boundaries_removed.len(),
    )
}

fn coverage_line(coverage: &CoverageComparison) -> String {
    format!(
        "coverage: considered {} -> {}, covered {} -> {}",
        count_label(coverage.from.considered),
        count_label(coverage.to.considered),
        count_label(coverage.from.covered),
        count_label(coverage.to.covered),
    )
}

fn count_label(count: Option<u64>) -> String {
    count.map_or_else(|| "unrecorded".to_string(), |count| count.to_string())
}

fn methodology_line(from: &ActiveThreatModel, to: &ActiveThreatModel, changed: bool) -> String {
    let state = if changed { "changed" } else { "unchanged" };
    format!(
        "methodology: {} -> {} ({state})",
        methodology_label(from),
        methodology_label(to)
    )
}

fn methodology_label(side: &ActiveThreatModel) -> String {
    document_methodology(&side.document).unwrap_or_else(|| "undeclared".to_string())
}

fn threat_detail_lines(threats: &ThreatSetDiff) -> Vec<String> {
    let all = threats
        .added
        .iter()
        .map(|threat| summary_line('+', threat))
        .chain(
            threats
                .removed
                .iter()
                .map(|threat| summary_line('-', threat)),
        )
        .chain(threats.changed.iter().map(change_line))
        .collect::<Vec<_>>();
    let hidden = all.len().saturating_sub(MAX_THREAT_DETAIL_LINES);
    let mut lines = all
        .into_iter()
        .take(MAX_THREAT_DETAIL_LINES)
        .collect::<Vec<_>>();
    if hidden > 0 {
        lines.push(format!("… {hidden} more threat change(s) in data.threats"));
    }
    lines
}

fn summary_line(marker: char, threat: &ThreatSummary) -> String {
    let impact = threat.impact.as_deref().unwrap_or("unrated");
    format!(
        "{marker} [{impact}] {}",
        threat_title(&threat.key, &threat.title)
    )
}

fn change_line(change: &ThreatFieldChange) -> String {
    format!(
        "~ {}: {}",
        threat_title(&change.key, &change.title),
        change.fields.join(", ")
    )
}

fn threat_title(key: &str, title: &Option<String>) -> String {
    title
        .as_deref()
        .map_or_else(|| key.to_string(), |title| format!("{title} ({key})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side(threats: Value) -> ActiveThreatModel {
        ActiveThreatModel {
            model_ref: ThreatModelRef {
                model_id: ThreatModelId::new(),
                revision_id: ThreatModelRevisionId::new(),
                sha256: format!("sha256:{}", "1".repeat(64)),
            },
            document: json!({"methodology": "stride", "threats": threats, "dfd": {}}),
        }
    }

    fn threats(count: usize) -> Value {
        let rows = (0..count)
            .map(|index| json!({"stableId": format!("tm-{index}"), "title": format!("T{index}")}))
            .collect::<Vec<_>>();
        json!(rows)
    }

    #[test]
    fn data_carries_both_sides_and_the_structural_diff() {
        let (from, to) = (side(threats(1)), side(threats(2)));
        let comparison = RevisionComparison::new(&from.document, &to.document);

        let data = threat_model_diff_data(&from, &to, &comparison).unwrap();

        assert_eq!(data["from"]["threatCount"], json!(1));
        assert_eq!(data["to"]["methodology"], json!("stride"));
        assert_eq!(data["to"]["revisionId"], json!(to.model_ref.revision_id));
        assert_eq!(data["threats"]["added"][0]["key"], json!("tm-1"));
        assert_eq!(data["methodologyChanged"], json!(false));
        assert!(data["coverage"]["from"]["considered"].is_null());
    }

    #[test]
    fn rendered_summary_caps_threat_detail_lines() {
        let (from, to) = (side(threats(0)), side(threats(13)));
        let comparison = RevisionComparison::new(&from.document, &to.document);

        let text = render_threat_model_diff(&from, &to, &comparison);

        assert!(text.contains("threats: 0 -> 13 (+13 added"), "{text}");
        assert!(text.contains("+ [unrated] T0 (tm-0)"), "{text}");
        assert!(text.contains("… 3 more threat change(s)"), "{text}");
        assert!(text.contains("covered unrecorded -> unrecorded"), "{text}");
        assert_eq!(
            diff_headline(&comparison),
            "threat-model diff: 0 context text change(s), 13 stored field change(s), 0 collection order change(s)"
        );
    }

    #[test]
    fn unresolved_selector_error_carries_its_cause_in_one_message() {
        let root = tempfile::tempdir().unwrap();
        let input = json!({"from": "tm_missing"});

        let error = load_diff_side(root.path(), &input, "from").unwrap_err();

        let message = error.to_string();
        assert!(
            message.contains("from=\"tm_missing\" did not resolve"),
            "{message}"
        );
        assert!(message.contains("manifest is missing"), "{message}");
        assert!(load_diff_side(root.path(), &input, "to").is_err());
    }

    #[test]
    fn headline_reports_identical_revisions() {
        let from = side(threats(2));
        let comparison = RevisionComparison::new(&from.document, &from.document);

        assert_eq!(
            diff_headline(&comparison),
            "threat-model diff: no differences"
        );
    }

    #[test]
    fn metadata_or_other_uncompared_changes_never_claim_identical_documents() {
        let from = side(threats(0));
        let mut to = from.clone();
        to.document["metadata"] = json!({"note":"Owned changed metadata"});
        let diff = diff_threat_model_documents(&from.document, &to.document);
        assert!(diff.is_empty());
        let data = threat_model_diff_data(
            &from,
            &to,
            &RevisionComparison::new(&from.document, &to.document),
        )
        .unwrap();
        assert_eq!(data["changedDocumentSections"], json!(["metadata"]));
        assert_eq!(data["documentChanged"], true);
        assert!(
            diff_headline(&RevisionComparison::new(&from.document, &to.document))
                .contains("1 stored field change(s)")
        );
    }
}

#[cfg(test)]
#[path = "diff_command/tests/dispatch.rs"]
mod dispatch_tests;
