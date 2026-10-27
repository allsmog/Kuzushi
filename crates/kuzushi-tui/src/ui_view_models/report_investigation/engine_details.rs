use super::*;

pub(super) fn append_document_engine_details(
    lines: &mut Vec<String>,
    document: &InvestigationReportDocument,
    details: bool,
) {
    let attempts = document.summary().attempts;
    let recorded = attempts
        .iter()
        .filter(|attempt| attempt.scan.is_some())
        .count();
    let mut engine_details = scan_detail_lines(recorded, attempts.len());
    if details {
        engine_details.extend(engine_detail_lines(document));
    }
    insert_engine_details(lines, engine_details);
    attempt_history::insert_after_scope(lines, attempts, details);
}

pub(super) fn insert_engine_details(lines: &mut Vec<String>, details: Vec<String>) {
    let index = lines
        .iter()
        .position(|line| line.starts_with("Work: ") || line.starts_with("Recurrence is"))
        .unwrap_or(1)
        .min(lines.len());
    lines.splice(index..index, details);
}

pub(super) fn engine_detail_lines(document: &InvestigationReportDocument) -> Vec<String> {
    summarize_engine_details(
        document
            .summary()
            .attempts
            .iter()
            .flat_map(|attempt| {
                attempt
                    .scan
                    .iter()
                    .flat_map(|receipt| receipt.scan.iter())
                    .flat_map(|scan| &scan.engines)
            })
            .filter_map(engine_detail_line),
    )
}

pub(super) fn summarize_engine_details(lines: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut counts = std::collections::BTreeMap::new();
    for line in lines {
        *counts.entry(line).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .map(|(line, count)| {
            if count == 1 {
                line
            } else {
                format!("{line} Recorded in {count} attempts.")
            }
        })
        .collect()
}

pub(super) fn engine_detail_line(
    engine: &kuzushi_core::run_artifacts::ScanStageEngine,
) -> Option<String> {
    engine
        .detail
        .as_ref()
        .map(|detail| format!("Engine {}: {detail}", engine.engine))
}

pub(super) fn scan_detail_lines(recorded: usize, attempted: usize) -> Vec<String> {
    if attempted == 0 {
        return Vec::new();
    }
    let missing = attempted.saturating_sub(recorded);
    let mut lines = vec![format!(
        "Engine details: {recorded} / {attempted} attempts recorded; {missing} unavailable."
    )];
    if missing > 0 {
        lines.push("Missing engine details do not establish coverage. Inspect incomplete run records before further work.".into());
    }
    lines
}
