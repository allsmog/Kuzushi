use crate::app::TargetCandidateFacts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetFactLabels {
    pub(crate) branch: String,
    pub(crate) revision: String,
    pub(crate) dirty: &'static str,
    pub(crate) files: String,
    pub(crate) languages: String,
    pub(crate) builds: String,
    pub(crate) scopes: String,
    pub(crate) prior: String,
}

pub(crate) fn target_fact_detail_lines(facts: &TargetCandidateFacts) -> [String; 3] {
    let labels = target_fact_labels(facts);
    [
        format!(
            "{} · {}@{} · {} · {}",
            facts.repository_kind, labels.branch, labels.revision, labels.dirty, labels.files
        ),
        format!("{} · {}", labels.languages, labels.builds),
        format!("{} · {}", labels.scopes, labels.prior),
    ]
}

pub(crate) fn target_fact_labels(facts: &TargetCandidateFacts) -> TargetFactLabels {
    TargetFactLabels {
        branch: branch_label(&facts.repository_kind, facts.branch.as_deref()),
        revision: facts
            .revision
            .as_deref()
            .map(|sha| sha.chars().take(10).collect())
            .unwrap_or_else(|| "-".to_string()),
        dirty: facts
            .dirty
            .map(|value| if value { "dirty" } else { "clean" })
            .unwrap_or("n/a"),
        files: format!(
            "{}{} files",
            facts.file_count,
            if facts.file_count_capped { "+" } else { "" }
        ),
        languages: joined_fact_label("languages", &facts.languages, "detecting"),
        builds: joined_fact_label("build", &facts.build_systems, "none detected"),
        scopes: joined_fact_label("nested scopes", &facts.nested_scopes, "none"),
        prior: prior_artifact_label(facts),
    }
}

fn branch_label(repository_kind: &str, branch: Option<&str>) -> String {
    match branch {
        Some(branch) => branch.to_string(),
        None if repository_kind == "git repository" => "detached HEAD".to_string(),
        None => "non-git".to_string(),
    }
}

fn joined_fact_label(label: &str, values: &[String], empty: &str) -> String {
    if values.is_empty() {
        format!("{label}: {empty}")
    } else {
        format!("{label}: {}", values.join(", "))
    }
}

fn prior_artifact_label(facts: &TargetCandidateFacts) -> String {
    if facts.prior_artifacts.is_empty() {
        return "prior Kuzushi: none".to_string();
    }
    format!(
        "prior Kuzushi: {} artifact(s) · {}",
        facts.prior_artifact_count,
        facts.prior_artifacts.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_label_distinguishes_detached_git_from_non_git() {
        assert_eq!(branch_label("git repository", None), "detached HEAD");
        assert_eq!(branch_label("source", None), "non-git");
        assert_eq!(branch_label("git repository", Some("main")), "main");
    }
}
