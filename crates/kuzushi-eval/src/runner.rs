use anyhow::{Context, Result};
use clap::Parser;
use std::fs;

use crate::{score, Cli, FindingsDump, MatchReport, Oracle};

pub(crate) fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let report = load_match_report(&cli)?;
    println!("{}", render_match_report(&report, cli.pretty)?);
    Ok(())
}

pub(crate) fn load_match_report(cli: &Cli) -> Result<MatchReport> {
    let oracle: Oracle = serde_json::from_str(
        &fs::read_to_string(&cli.oracle)
            .with_context(|| format!("read oracle {}", cli.oracle.display()))?,
    )
    .with_context(|| format!("parse oracle {}", cli.oracle.display()))?;

    let findings: FindingsDump = serde_json::from_str(
        &fs::read_to_string(&cli.findings)
            .with_context(|| format!("read findings {}", cli.findings.display()))?,
    )
    .with_context(|| format!("parse findings {}", cli.findings.display()))?;

    let target = cli.target.canonicalize().unwrap_or(cli.target.clone());
    Ok(score(cli, &oracle, &findings, &target))
}

pub(crate) fn render_match_report(report: &MatchReport, pretty: bool) -> Result<String> {
    let output = if pretty {
        serde_json::to_string_pretty(report)?
    } else {
        serde_json::to_string(report)?
    };
    Ok(output)
}
