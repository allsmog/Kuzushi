use std::collections::BTreeMap;

use anyhow::Result;
use kuzushi_core::review_yield::domain::CensusReport;

pub(crate) fn review_yield_census_output(report: &CensusReport, json: bool) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(report)?));
    }
    Ok(census_plain(report))
}

fn census_plain(report: &CensusReport) -> String {
    let mut lines = vec!["Review-yield census".to_string()];
    lines.extend(totals_lines(report));
    lines.extend(exclusion_lines(report));
    lines.extend(breakdown_lines(report));
    lines.push(next_step(report));
    format!("{}\n", lines.join("\n"))
}

fn totals_lines(report: &CensusReport) -> Vec<String> {
    vec![
        row("Decision events", report.decision_events),
        row("Human decision events", report.human_decision_events),
        row("Adjudicated identities", report.adjudicated_identities),
        row("Exportable examples", report.eligible_identities),
        row("Confirmed real", report.positive),
        row("Rejected false positive", report.negative),
    ]
}

fn exclusion_lines(report: &CensusReport) -> Vec<String> {
    vec![
        row("Conflicting reversals", report.conflicted),
        row("Policy-only outcomes", report.no_eligible_label),
        row("Policy transitions", report.policy_transitions),
        row("Missing read cutoff", report.missing_exact_cutoff),
        row("Missing durable identity", report.missing_durable_identity),
        row(
            "Missing pre-cutoff snapshot",
            report.missing_pre_cutoff_observation,
        ),
    ]
}

fn breakdown_lines(report: &CensusReport) -> Vec<String> {
    let mut lines = vec![
        row("Exact read cutoff", cutoff(report, "tui_read_watermark")),
        row("Head-barrier cutoff", cutoff(report, "barrier_at_head")),
        row("No usable cutoff", cutoff(report, "missing")),
        row("Distinct repositories", report.distinct_repositories),
        row("Distinct tool families", report.distinct_tool_families),
        row("Distinct rule families", report.distinct_rule_families),
    ];
    lines.push(map_line("Decisions by author", &report.by_author));
    lines.push(map_line(
        "Excluded by dismiss reason",
        &report.by_dismiss_reason,
    ));
    lines
}

fn next_step(report: &CensusReport) -> String {
    if report.eligible_identities == 0 {
        return "Next: adjudicate findings in the review surface, then re-run this census."
            .to_string();
    }
    "Next: kuzushi --target <repo> review-yield export --out <file>".to_string()
}

fn cutoff(report: &CensusReport, key: &str) -> u64 {
    report.cutoff_quality.get(key).copied().unwrap_or(0)
}

fn map_line(label: &str, counts: &BTreeMap<String, u64>) -> String {
    let rendered = counts
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<String>>()
        .join(" ");
    let value = if rendered.is_empty() {
        "-".to_string()
    } else {
        rendered
    };
    format!("{label:<30}{value}")
}

fn row(label: &str, value: u64) -> String {
    format!("{label:<30}{value}")
}
