use super::*;

#[derive(Debug, Clone, Default)]
pub struct PrCommentInput {
    pub repo_name: Option<String>,
    pub findings: Vec<Finding>,
    pub cost_usd: f64,
    pub elapsed: Option<Duration>,
    pub run_url: Option<String>,
    pub top_n: Option<usize>,
    pub kuzushi_version: Option<String>,
    pub model: Option<String>,
    pub git_sha: Option<String>,
    pub run_id: Option<String>,
    pub changed_files: Vec<String>,
}

pub fn build_pr_comment(input: &PrCommentInput) -> String {
    let repo_name = input
        .repo_name
        .clone()
        .unwrap_or_else(|| "(unknown repo)".to_string());
    let top_n = input.top_n.unwrap_or(10);

    let aliased = sorted_finding_aliases(&input.findings);
    let sorted = aliased
        .iter()
        .map(|(_, finding)| finding.clone())
        .collect::<Vec<_>>();

    let changed = changed_set(&input.changed_files);
    let new_in_pr: Vec<(String, Finding)> = aliased
        .iter()
        .filter(|(_, finding)| {
            changed
                .as_ref()
                .is_some_and(|set| in_changed(&finding.file_path, set))
        })
        .cloned()
        .collect();

    let header_suffix = input
        .run_url
        .as_deref()
        .map(|url| format!(" · [run]({url})"))
        .unwrap_or_default();
    let header = format!("### 🔐 Kuzushi scan · `{repo_name}`{header_suffix}");
    let verdict = render_verdict_counts(&sorted, new_in_pr.len(), changed.is_some());
    let cost = render_cost_line(input);

    let mut sections: Vec<String> = vec![header, String::new(), verdict, String::new(), cost];

    if let Some(_set) = changed {
        if !new_in_pr.is_empty() {
            sections.push(String::new());
            sections.push(render_findings_block(
                "New in this PR",
                &new_in_pr,
                input.run_url.as_deref(),
                new_in_pr.len(),
                None,
            ));
        }
    }

    let total = sorted.len();
    let truncated = aliased.iter().take(top_n).cloned().collect::<Vec<_>>();
    sections.push(String::new());
    sections.push(render_findings_block(
        &format!("Top findings ({} of {total})", truncated.len().min(top_n)),
        &truncated,
        input.run_url.as_deref(),
        total,
        Some(top_n),
    ));

    sections.push(String::new());
    sections.push(render_footer(input, top_n, total));
    sections.push(String::new());
    sections.join("\n")
}

pub(crate) fn changed_set(files: &[String]) -> Option<HashSet<String>> {
    if files.is_empty() {
        return None;
    }
    Some(
        files
            .iter()
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect(),
    )
}

pub(crate) fn in_changed(file_path: &str, changed: &HashSet<String>) -> bool {
    if changed.contains(file_path) {
        return true;
    }
    changed
        .iter()
        .any(|f| file_path.ends_with(f.as_str()) || f.ends_with(file_path))
}
