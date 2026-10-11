use super::formatting::*;
use super::*;

pub(super) fn render_bundle_readme_markdown(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: &WorkspaceExportOptions,
    total_count: usize,
) -> String {
    let mut out = String::new();
    push_readme_header(&mut out, workspace, records, options, total_count);
    push_readme_summary(&mut out, records);
    push_readme_findings_table(&mut out, records);
    out
}

fn push_readme_header(
    out: &mut String,
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: &WorkspaceExportOptions,
    total_count: usize,
) {
    out.push_str("# Kuzushi findings bundle\n\n");
    out.push_str(
        "Kuzushi combines scanner output with automated, AI-assisted security analysis. \
         Treat each finding as a review candidate, not as proof by itself.\n\n",
    );
    out.push_str(
        "Proof bands describe evidence: `confirmed` means authenticated runtime reproduction; \
         `likely` means linked static or code evidence; `unverified` has not been promoted beyond \
         a signal; `dismissed` was rejected or suppressed.\n\n",
    );
    out.push_str(&format!(
        "- **Target:** {}\n",
        markdown_code_span(&workspace.root().display().to_string())
    ));
    out.push_str(&format!(
        "- **Finding selection:** `{}`\n",
        options.completeness.as_str()
    ));
    out.push_str(&format!(
        "- **Included:** {} of {} finding(s)\n",
        records.len(),
        total_count
    ));
    out.push_str(
        "- **Field coverage:** human-readable subset; see \
         `manifest.json` → `metadata.omittedFields`\n\n",
    );
}

fn push_readme_summary(out: &mut String, records: &[WorkspaceFindingExportRecord]) {
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- **Severity:** {}\n",
        projection_count_summary(records, |record| record.severity.as_str())
    ));
    out.push_str(&format!(
        "- **Review decisions:** {}\n",
        projection_count_summary(records, |record| record.review_decision.as_str())
    ));
    out.push_str(&format!(
        "- **Evidence states:** {}\n\n",
        projection_count_summary(records, |record| record.evidence.state.as_str())
    ));
}

fn projection_count_summary(
    records: &[WorkspaceFindingExportRecord],
    key: impl Fn(&WorkspaceFindingExportRecord) -> &str,
) -> String {
    let mut counts = BTreeMap::<String, usize>::new();
    for record in records {
        *counts.entry(key(record).to_string()).or_default() += 1;
    }
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .into_iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn push_readme_findings_table(out: &mut String, records: &[WorkspaceFindingExportRecord]) {
    out.push_str("## Findings\n\n");
    out.push_str(
        "| Alias | Severity | Proof band | Decision | Lifecycle | Evidence | Location |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for record in records {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_table_cell(&record.alias),
            markdown_table_cell(&record.severity),
            markdown_table_cell(&record.proof_confidence),
            markdown_table_cell(&record.review_decision),
            markdown_table_cell(&record.lifecycle_status),
            markdown_table_cell(&record.evidence.state),
            markdown_table_cell(&markdown_code_span(&format!(
                "{}:{}",
                record.location.file, record.location.start_line
            )))
        ));
    }
    if records.is_empty() {
        out.push_str("| - | - | - | - | - | - | - |\n");
    }
    out.push('\n');
}
