use std::collections::HashSet;
use std::time::Duration;

use crate::findings::{sorted_finding_aliases, Finding, Severity};

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

fn changed_set(files: &[String]) -> Option<HashSet<String>> {
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

fn in_changed(file_path: &str, changed: &HashSet<String>) -> bool {
    if changed.contains(file_path) {
        return true;
    }
    changed
        .iter()
        .any(|f| file_path.ends_with(f.as_str()) || f.ends_with(file_path))
}

fn render_verdict_counts(findings: &[Finding], new_in_pr: usize, diff_scoped: bool) -> String {
    let mut parts = Vec::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let count = findings.iter().filter(|f| f.severity == severity).count();
        if count > 0 {
            parts.push(format!(
                "{} **{count} {}**",
                severity_icon(severity),
                severity.as_str()
            ));
        }
    }
    if parts.is_empty() {
        return "**No findings triaged.**".to_string();
    }
    if diff_scoped {
        parts.push(format!("🆕 **{new_in_pr} new in this PR**"));
    }
    parts.join(" · ")
}

fn render_cost_line(input: &PrCommentInput) -> String {
    let elapsed = input
        .elapsed
        .map(format_duration)
        .map(|d| format!(" in {d}"))
        .unwrap_or_default();
    format!("💸 total **${:.2}**{elapsed}", input.cost_usd.max(0.0))
}

fn render_findings_block(
    heading: &str,
    rows: &[(String, Finding)],
    run_url: Option<&str>,
    total: usize,
    top_n: Option<usize>,
) -> String {
    if rows.is_empty() {
        return format!("#### {heading}\n\n_No true-positive findings._");
    }
    let mut out = vec![
        format!("#### {heading}"),
        String::new(),
        "| ID | Severity | Title | Location |".to_string(),
        "|----|----------|-------|----------|".to_string(),
    ];
    for (alias, f) in rows {
        let id_cell = match run_url {
            Some(url) => format!("[{alias}]({url}#{alias})"),
            None => alias.clone(),
        };
        let severity = severity_badge(f.severity);
        let title = escape_md(&f.title);
        let location = format!("`{}:{}`", f.file_path, f.start_line);
        out.push(format!("| {id_cell} | {severity} | {title} | {location} |"));
    }
    if let Some(top_n) = top_n {
        if total > rows.len() {
            out.push(String::new());
            out.push(format!(
                "_… and **{}** more findings (truncated; raise `topN` to see them)._",
                total - rows.len()
            ));
            let _ = top_n;
        }
    }
    out.join("\n")
}

fn render_footer(input: &PrCommentInput, top_n: usize, total: usize) -> String {
    let mut stamps = Vec::new();
    match input.kuzushi_version.as_deref() {
        Some(version) => stamps.push(format!("Kuzushi {version}")),
        None => stamps.push("Kuzushi".to_string()),
    }
    if let Some(run_id) = input.run_id.as_deref() {
        stamps.push(format!("run `{}`", short(run_id, 8)));
    }
    if let Some(model) = input.model.as_deref() {
        stamps.push(format!("model `{model}`"));
    }
    if let Some(sha) = input.git_sha.as_deref() {
        stamps.push(format!("git `{}`", short(sha, 7)));
    }
    let stamp = stamps.join(" · ");
    let truncated = total.saturating_sub(top_n);
    let truncated_note = if total == 0 {
        format!("Showing top {top_n}.")
    } else {
        let shown = top_n.min(total);
        format!("Showing top {shown}; {truncated} truncated.")
    };
    format!(
        "<sub>Generated by [{stamp}](https://github.com/allsmog/Kuzushi). {truncated_note}</sub>"
    )
}

fn severity_icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "🟥",
        Severity::High => "🟧",
        Severity::Medium => "🟨",
        _ => "⬜",
    }
}

fn severity_badge(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "🟥 CRIT",
        Severity::High => "🟧 HIGH",
        Severity::Medium => "🟨 MED",
        _ => "⬜ LOW",
    }
}

fn escape_md(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn short(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

fn format_duration(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let m = secs / 60;
    let s = secs % 60;
    if s == 0 {
        format!("{m}m")
    } else {
        format!("{m}m {s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: Severity, fp: &str, title: &str) -> Finding {
        Finding {
            id: None,
            scan_id: None,
            fingerprint: fp.to_string(),
            rule_id: "test/rule".to_string(),
            title: title.to_string(),
            severity,
            file_path: "src/x.rs".to_string(),
            start_line: 1,
            end_line: None,
            message: String::new(),
            tool: "test".to_string(),
            actor_fingerprint: None,
            static_proof_state: None,
            triage: None,
            verification: None,
            created_at: String::new(),
            vuln_source: None,
            dedup_key: None,
        }
    }

    #[test]
    fn header_uses_repo_name_and_run_url() {
        let input = PrCommentInput {
            repo_name: Some("acme-api".to_string()),
            run_url: Some("https://example/run/1".to_string()),
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("### 🔐 Kuzushi scan · `acme-api`"));
        assert!(body.contains("[run](https://example/run/1)"));
    }

    #[test]
    fn empty_findings_render_no_findings_block() {
        let body = build_pr_comment(&PrCommentInput::default());
        assert!(body.contains("**No findings triaged.**"));
        assert!(body.contains("_No true-positive findings._"));
    }

    #[test]
    fn findings_table_includes_severity_badge_and_alias() {
        let input = PrCommentInput {
            findings: vec![
                make_finding(Severity::High, "fhigh", "ssrf in admin"),
                make_finding(Severity::Critical, "fcrit", "sqli"),
            ],
            cost_usd: 0.42,
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("F-0001"));
        assert!(body.contains("F-0002"));
        assert!(body.contains("🟥 CRIT"));
        assert!(body.contains("🟧 HIGH"));
        assert!(body.contains("$0.42"));
        // critical-first ordering
        let crit_pos = body.find("F-0001").unwrap();
        let high_pos = body.find("F-0002").unwrap();
        assert!(crit_pos < high_pos);
        // critical row should be the SQLI finding (sorted to top).
        let crit_row_start = body[crit_pos..].find("|").unwrap() + crit_pos;
        let crit_row_end = body[crit_row_start..].find('\n').unwrap() + crit_row_start;
        assert!(body[crit_row_start..crit_row_end].contains("sqli"));
    }

    #[test]
    fn diff_section_preserves_global_stable_aliases() {
        let mut critical = make_finding(Severity::Critical, "fcrit", "global critical");
        critical.file_path = "src/old.rs".to_string();
        let input = PrCommentInput {
            findings: vec![
                critical,
                make_finding(Severity::High, "fhigh", "changed high"),
            ],
            changed_files: vec!["src/x.rs".to_string()],
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);

        let new_section = body
            .split("#### New in this PR")
            .nth(1)
            .and_then(|section| section.split("#### Top findings").next())
            .unwrap_or("");

        assert!(new_section.contains("F-0002"));
        assert!(!new_section.contains("F-0001"));
    }

    #[test]
    fn top_n_truncates_and_emits_truncation_note() {
        let findings: Vec<Finding> = (0..15)
            .map(|i| make_finding(Severity::Medium, &format!("fp-{i:02}"), "x"))
            .collect();
        let input = PrCommentInput {
            findings,
            top_n: Some(5),
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("**10** more findings"));
        assert!(body.contains("Top findings (5 of 15)"));
    }

    #[test]
    fn changed_files_emits_new_in_pr_block() {
        let mut finding = make_finding(Severity::High, "fp1", "diff hit");
        finding.file_path = "src/admin.rs".to_string();
        let input = PrCommentInput {
            findings: vec![finding],
            changed_files: vec!["src/admin.rs".to_string()],
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("New in this PR"));
        assert!(body.contains("🆕 **1 new in this PR**"));
    }

    #[test]
    fn footer_includes_optional_stamps_truncated() {
        let input = PrCommentInput {
            findings: (0..3)
                .map(|i| make_finding(Severity::Low, &format!("f-{i}"), "x"))
                .collect(),
            kuzushi_version: Some("0.24.0-alpha.0".to_string()),
            model: Some("openai:gpt-5.5".to_string()),
            git_sha: Some("abcdef1234567890".to_string()),
            run_id: Some("12345678-aaaa-bbbb-cccc-ddddeeeeffff".to_string()),
            top_n: Some(2),
            ..PrCommentInput::default()
        };
        let body = build_pr_comment(&input);
        assert!(body.contains("Kuzushi 0.24.0-alpha.0"));
        assert!(body.contains("model `openai:gpt-5.5`"));
        assert!(body.contains("git `abcdef1`"));
        assert!(body.contains("run `12345678`"));
        assert!(body.contains("Showing top 2; 1 truncated"));
    }
}
