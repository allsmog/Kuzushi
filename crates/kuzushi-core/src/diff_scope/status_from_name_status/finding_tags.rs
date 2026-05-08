use super::*;

pub(in crate::diff_scope) fn insert_context(
    contexts: &mut BTreeMap<String, DiffContext>,
    context: DiffContext,
) {
    let key = format!(
        "{:?}:{}:{:?}:{}",
        context.kind, context.path, context.line, context.detail
    );
    contexts.entry(key).or_insert(context);
}

pub(in crate::diff_scope) fn tag_current_finding(
    finding: &Finding,
    changed_files: &[ChangedFile],
) -> DiffFindingTag {
    let Some(file) = changed_files
        .iter()
        .find(|file| file.path == finding.file_path)
    else {
        return diff_finding_tag(
            finding,
            DiffFindingStatus::Existing,
            "finding is outside changed files",
        );
    };
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    if file.status == DiffFileStatus::Added
        || ranges_overlap(finding.start_line, end_line, &file.changed_ranges)
    {
        return diff_finding_tag(
            finding,
            DiffFindingStatus::New,
            "finding source span overlaps PR changed lines",
        );
    }
    diff_finding_tag(
        finding,
        DiffFindingStatus::ChangedContext,
        "finding is in a changed file but outside changed lines",
    )
}

pub(in crate::diff_scope) fn tag_fixed_findings(
    previous_findings: &[Finding],
    current_findings: &[Finding],
    changed_files: &[ChangedFile],
) -> Vec<DiffFindingTag> {
    let current = current_findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let mut fixed = Vec::new();
    let mut seen = BTreeSet::new();
    for finding in previous_findings {
        if current.contains(finding.fingerprint.as_str()) || !seen.insert(&finding.fingerprint) {
            continue;
        }
        let Some(file) = changed_files.iter().find(|file| {
            file.path == finding.file_path
                || file.previous_path.as_deref() == Some(finding.file_path.as_str())
        }) else {
            continue;
        };
        let end_line = finding.end_line.unwrap_or(finding.start_line);
        if file.status == DiffFileStatus::Deleted
            || ranges_overlap(finding.start_line, end_line, &file.deleted_ranges)
        {
            fixed.push(diff_finding_tag(
                finding,
                DiffFindingStatus::Fixed,
                "previous finding no longer appears and its old source span was changed or deleted",
            ));
        }
    }
    fixed
}

pub(in crate::diff_scope) fn diff_finding_tag(
    finding: &Finding,
    status: DiffFindingStatus,
    reason: &str,
) -> DiffFindingTag {
    DiffFindingTag {
        fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        status,
        reason: reason.to_string(),
    }
}
