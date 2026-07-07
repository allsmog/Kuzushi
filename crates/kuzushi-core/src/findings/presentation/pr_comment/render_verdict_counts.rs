use super::*;

pub(crate) fn render_verdict_counts(
    findings: &[Finding],
    new_in_pr: usize,
    diff_scoped: bool,
) -> String {
    let mut parts = severity_count_parts(findings);
    if parts.is_empty() {
        return "**No findings triaged.**".to_string();
    }
    append_diff_count(&mut parts, new_in_pr, diff_scoped);
    parts.join(" · ")
}

fn severity_count_parts(findings: &[Finding]) -> Vec<String> {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter_map(|severity| severity_count_part(findings, severity))
    .collect()
}

fn severity_count_part(findings: &[Finding], severity: Severity) -> Option<String> {
    let count = findings.iter().filter(|f| f.severity == severity).count();
    (count > 0).then(|| {
        format!(
            "{} **{count} {}**",
            severity_icon(severity),
            severity.as_str()
        )
    })
}

fn append_diff_count(parts: &mut Vec<String>, new_in_pr: usize, diff_scoped: bool) {
    if diff_scoped {
        parts.push(format!("🆕 **{new_in_pr} new in this PR**"));
    }
}

pub(crate) fn render_cost_line(input: &PrCommentInput) -> String {
    let elapsed = input
        .elapsed
        .map(format_duration)
        .map(|d| format!(" in {d}"))
        .unwrap_or_default();
    let phase_costs = render_phase_costs(&input.phase_costs);
    format!(
        "💸 total **${:.2}**{elapsed}{phase_costs}",
        input.cost_usd.max(0.0)
    )
}

fn render_phase_costs(costs: &[PrCommentPhaseCost]) -> String {
    if costs.is_empty() {
        return String::new();
    }
    let parts = costs
        .iter()
        .filter(|cost| cost.cost_usd.is_finite() && cost.cost_usd > 0.0)
        .take(4)
        .map(phase_cost_part)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" · {}", parts.join(" · "))
    }
}

fn phase_cost_part(cost: &PrCommentPhaseCost) -> String {
    format!("{} **${:.2}**", escape_md(&cost.label), cost.cost_usd)
}

pub(crate) fn render_findings_block(
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
        "| ID | Severity | Confidence | CWE | Title | Location |".to_string(),
        "|----|----------|------------|-----|-------|----------|".to_string(),
    ];
    for (alias, f) in rows {
        out.push(finding_table_row(alias, f, run_url));
    }
    append_finding_evidence_lines(&mut out, rows);
    append_findings_truncation(&mut out, rows.len(), total, top_n);
    out.join("\n")
}

fn finding_table_row(alias: &str, finding: &Finding, run_url: Option<&str>) -> String {
    format!(
        "| {} | {} | {} | {} | {} | `{}` |",
        finding_id_cell(alias, run_url),
        severity_badge(finding.severity),
        ProofConfidence::classify(finding).label(),
        escape_md(&finding_cwe_label(finding)),
        escape_md(&finding.title),
        finding_location(finding)
    )
}

fn finding_id_cell(alias: &str, run_url: Option<&str>) -> String {
    run_url
        .map(|url| format!("[{alias}]({url}#{alias})"))
        .unwrap_or_else(|| alias.to_string())
}

fn append_finding_evidence_lines(out: &mut Vec<String>, rows: &[(String, Finding)]) {
    out.push(String::new());
    for (alias, finding) in rows {
        out.push(format!(
            "> **{} evidence:** {}",
            alias,
            escape_md(&finding_evidence_preview(finding))
        ));
        if let Some(remediation) = finding_remediation_hint(finding) {
            out.push(format!(
                "> **{} remediation:** {}",
                alias,
                escape_md(&remediation)
            ));
        }
    }
}

fn append_findings_truncation(
    out: &mut Vec<String>,
    row_count: usize,
    total: usize,
    top_n: Option<usize>,
) {
    if top_n.is_none() || total <= row_count {
        return;
    }
    out.push(String::new());
    out.push(format!(
        "_… and **{}** more findings (truncated; raise `topN` to see them)._",
        total - row_count
    ));
}

pub(crate) fn render_chains_block(chains: &[PrCommentChain]) -> String {
    let mut out = vec![
        format!("#### Exploit chains ({})", chains.len()),
        String::new(),
    ];
    for chain in chains.iter().take(3) {
        out.push(format!(
            "- **{} · {} · {} {}** - {}",
            escape_md(&chain.id),
            escape_md(&chain.severity.to_ascii_uppercase()),
            chain.steps.len(),
            pluralize("step", chain.steps.len()),
            escape_md(&chain.title)
        ));
        render_chain_steps(&mut out, &chain.steps);
    }
    if chains.len() > 3 {
        out.push(format!("- ... and {} more chain(s)", chains.len() - 3));
    }
    out.join("\n")
}

fn render_chain_steps(out: &mut Vec<String>, steps: &[PrCommentChainStep]) {
    for step in steps.iter().take(4) {
        out.push(format!(
            "  - {} `{}` - {}",
            escape_md(&step.role),
            chain_step_location(step),
            escape_md(&step.description)
        ));
    }
    if steps.len() > 4 {
        out.push(format!("  - ... and {} more step(s)", steps.len() - 4));
    }
}

fn chain_step_location(step: &PrCommentChainStep) -> String {
    format!("{}:{}", step.file_path, step.start_line.max(1))
}

fn pluralize(word: &str, count: usize) -> String {
    if count == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

pub(crate) fn render_footer(input: &PrCommentInput, top_n: usize, total: usize) -> String {
    let stamp = footer_stamps(input).join(" · ");
    let truncated_note = footer_truncation_note(top_n, total);
    format!(
        "<sub>Generated by [{stamp}](https://github.com/allsmog/Kuzushi). {truncated_note}</sub>"
    )
}

fn footer_stamps(input: &PrCommentInput) -> Vec<String> {
    let mut stamps = vec![version_stamp(input.kuzushi_version.as_deref())];
    stamps.extend(optional_footer_stamps(input));
    stamps
}

fn version_stamp(version: Option<&str>) -> String {
    version
        .map(|version| format!("Kuzushi {version}"))
        .unwrap_or_else(|| "Kuzushi".to_string())
}

fn optional_footer_stamps(input: &PrCommentInput) -> Vec<String> {
    [
        input
            .run_id
            .as_deref()
            .map(|run_id| format!("run `{}`", short(run_id, 8))),
        input
            .model
            .as_deref()
            .map(|model| format!("model `{model}`")),
        input
            .git_sha
            .as_deref()
            .map(|sha| format!("git `{}`", short(sha, 7))),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn footer_truncation_note(top_n: usize, total: usize) -> String {
    if total == 0 {
        return format!("Showing top {top_n}.");
    }
    let shown = top_n.min(total);
    let truncated = total.saturating_sub(top_n);
    format!("Showing top {shown}; {truncated} truncated.")
}
