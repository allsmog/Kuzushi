use super::*;

#[derive(Debug, Clone, Default)]
pub struct PrCommentInput {
    pub repo_name: Option<String>,
    pub findings: Vec<Finding>,
    pub chains: Vec<PrCommentChain>,
    pub cost_usd: f64,
    pub phase_costs: Vec<PrCommentPhaseCost>,
    pub elapsed: Option<Duration>,
    pub run_url: Option<String>,
    pub top_n: Option<usize>,
    pub kuzushi_version: Option<String>,
    pub model: Option<String>,
    pub git_sha: Option<String>,
    pub run_id: Option<String>,
    pub changed_files: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PrCommentPhaseCost {
    pub label: String,
    pub cost_usd: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrCommentChain {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub steps: Vec<PrCommentChainStep>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrCommentChainStep {
    pub role: String,
    pub description: String,
    pub file_path: String,
    pub start_line: u32,
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

    let mut sections = header_sections(
        input,
        &repo_name,
        &sorted,
        new_in_pr.len(),
        changed.is_some(),
    );
    append_chain_sections(&mut sections, input);
    append_new_in_pr_sections(&mut sections, input, changed.is_some(), &new_in_pr);

    let total = sorted.len();
    let truncated = aliased.iter().take(top_n).cloned().collect::<Vec<_>>();
    append_top_findings_sections(&mut sections, input, top_n, total, &truncated);
    append_footer_sections(&mut sections, input, top_n, total);
    sections.push(String::new());
    sections.join("\n")
}

fn header_sections(
    input: &PrCommentInput,
    repo_name: &str,
    sorted: &[Finding],
    new_in_pr_count: usize,
    diff_scoped: bool,
) -> Vec<String> {
    let header_suffix = input
        .run_url
        .as_deref()
        .map(|url| format!(" · [run]({url})"))
        .unwrap_or_default();
    vec![
        format!("### 🔐 Kuzushi scan · `{repo_name}`{header_suffix}"),
        String::new(),
        render_verdict_counts(sorted, new_in_pr_count, diff_scoped),
        String::new(),
        render_cost_line(input),
    ]
}

fn append_chain_sections(sections: &mut Vec<String>, input: &PrCommentInput) {
    if input.chains.is_empty() {
        return;
    }
    sections.push(String::new());
    sections.push(render_chains_block(&input.chains));
}

fn append_new_in_pr_sections(
    sections: &mut Vec<String>,
    input: &PrCommentInput,
    diff_scoped: bool,
    new_in_pr: &[(String, Finding)],
) {
    if !diff_scoped || new_in_pr.is_empty() {
        return;
    }
    sections.push(String::new());
    sections.push(render_findings_block(
        "New in this PR",
        new_in_pr,
        input.run_url.as_deref(),
        new_in_pr.len(),
        None,
    ));
}

fn append_top_findings_sections(
    sections: &mut Vec<String>,
    input: &PrCommentInput,
    top_n: usize,
    total: usize,
    truncated: &[(String, Finding)],
) {
    sections.push(String::new());
    sections.push(render_findings_block(
        &format!("Top findings ({} of {total})", truncated.len().min(top_n)),
        truncated,
        input.run_url.as_deref(),
        total,
        Some(top_n),
    ));
}

fn append_footer_sections(
    sections: &mut Vec<String>,
    input: &PrCommentInput,
    top_n: usize,
    total: usize,
) {
    sections.push(String::new());
    sections.push(render_footer(input, top_n, total));
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
