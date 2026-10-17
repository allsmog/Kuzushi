use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangedPathLimits {
    pub max_changed_files: usize,
    pub max_git_output_bytes: usize,
    pub git_timeout_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommittedPathComparison {
    pub base_commit: String,
    pub merge_base: String,
    pub head_commit: String,
    pub repository_prefix: String,
    pub changed_files: Vec<String>,
    pub total_changed_files: usize,
    pub omitted_changed_files: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChangedPathReviewHint {
    pub file_path: String,
    pub rule_id: &'static str,
    pub reason: &'static str,
}

pub(crate) fn review_hint(path: &str, repository_prefix: &str) -> Option<ChangedPathReviewHint> {
    let repository_path = format!("{repository_prefix}{path}");
    let rule_id = super::hot_paths::hot_path_rule_id(&repository_path)?;
    Some(ChangedPathReviewHint {
        file_path: path.to_owned(),
        rule_id,
        reason: "Changed path matches a recorded review pattern. Source inspection is required before deciding whether to scan.",
    })
}
