use anyhow::{Context, Result};
use clap::Parser;
use std::fs;

use crate::{score, Cli, FindingsDump, MatchReport, Oracle};

pub(crate) fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let report = load_match_report(&cli)?;
    println!("{}", render_match_report(&report, cli.pretty)?);
    enforce_threshold(&report, cli.enforce_threshold)?;
    Ok(())
}

pub(crate) fn load_match_report(cli: &Cli) -> Result<MatchReport> {
    let oracle: Oracle = serde_json::from_str(
        &fs::read_to_string(&cli.oracle)
            .with_context(|| format!("read oracle {}", cli.oracle.display()))?,
    )
    .with_context(|| format!("parse oracle {}", cli.oracle.display()))?;

    let raw: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&cli.findings)
            .with_context(|| format!("read findings {}", cli.findings.display()))?,
    )
    .with_context(|| format!("parse findings {}", cli.findings.display()))?;
    validate_complete_findings(&raw)?;
    let findings: FindingsDump = serde_json::from_value(raw)?;
    validate_threshold(oracle.expected_min_recall)?;

    let target = cli.target.canonicalize().unwrap_or(cli.target.clone());
    Ok(score(cli, &oracle, &findings, &target))
}

fn validate_complete_findings(raw: &serde_json::Value) -> Result<()> {
    let rows = raw
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .context("findings export has no findings array")?;
    anyhow::ensure!(
        raw.get("truncated") != Some(&serde_json::json!(true)),
        "truncated findings export"
    );
    for field in ["count", "total", "total_count"] {
        if let Some(total) = raw.get(field) {
            anyhow::ensure!(
                total.as_u64() == Some(rows.len() as u64),
                "incomplete findings export: {field} disagrees with row count"
            );
        }
    }
    Ok(())
}

fn validate_threshold(threshold: Option<f64>) -> Result<()> {
    if let Some(value) = threshold {
        anyhow::ensure!(
            value.is_finite() && (0.0..=1.0).contains(&value),
            "expected_min_recall must be between 0 and 1"
        );
    }
    Ok(())
}

pub(crate) fn enforce_threshold(report: &MatchReport, enforce: bool) -> Result<()> {
    anyhow::ensure!(
        !enforce || report.recall.pm_lines >= report.expected_min_recall,
        "recall regression: measured {} below required {}",
        report.recall.pm_lines,
        report.expected_min_recall
    );
    Ok(())
}

#[cfg(test)]
mod completeness_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn truncated_exports_are_rejected_and_complete_large_exports_are_accepted() {
        assert!(validate_complete_findings(
            &json!({"count": 501, "findings": vec![json!({}); 500]})
        )
        .is_err());
        assert!(validate_complete_findings(
            &json!({"count": 501, "findings": vec![json!({}); 501]})
        )
        .is_ok());
        assert!(validate_complete_findings(&json!({"findings": [], "truncated": true})).is_err());
        assert!(validate_complete_findings(&json!({"count": 0, "findings": []})).is_ok());
    }
}

pub(crate) fn render_match_report(report: &MatchReport, pretty: bool) -> Result<String> {
    let output = if pretty {
        serde_json::to_string_pretty(report)?
    } else {
        serde_json::to_string(report)?
    };
    Ok(output)
}
