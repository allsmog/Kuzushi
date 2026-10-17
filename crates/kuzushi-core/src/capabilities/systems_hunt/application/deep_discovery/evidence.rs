use super::super::source_context::prefix;
use super::*;
use crate::FindingEvidence;

pub(super) fn attach(
    findings: &mut [Finding],
    raw: &Value,
    prepared: &context::Prepared,
) -> Result<()> {
    let rows = raw["findings"]
        .as_array()
        .context("Parsed finding rows are missing")?;
    anyhow::ensure!(
        findings.len() == rows.len(),
        "Parsed findings changed during normalization; no ledger publication started"
    );
    for (finding, row) in findings.iter_mut().zip(rows) {
        let mut evidence = vec![FindingEvidence {
            kind: FindingEvidence::UNSCORED_MODEL_CLAIM.into(),
            file_path: finding.file_path.clone(),
            line: finding.start_line,
            rationale: format!("Unverified model claim; unscored.\n{}", finding.message),
            ..Default::default()
        }];
        append_citations(&mut evidence, row, prepared)?;
        finding.evidence = evidence;
    }
    Ok(())
}

fn append_citations(
    evidence: &mut Vec<FindingEvidence>,
    row: &Value,
    prepared: &context::Prepared,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in row["evidence"]
        .as_array()
        .context("Parsed citations are missing")?
    {
        let text = value.as_str().context("Parsed citation must be text")?;
        let anchor = text.split(" - ").next().unwrap_or(text);
        let (path, line) = anchor
            .rsplit_once(':')
            .context("Parsed citation has no line")?;
        let line: u32 = line.parse()?;
        if seen.insert((path.to_owned(), line)) {
            evidence.push(citation(prepared, path, line)?);
        }
    }
    Ok(())
}

fn citation(prepared: &context::Prepared, path: &str, line: u32) -> Result<FindingEvidence> {
    let source = prepared
        .sources
        .get(path)
        .context("Parsed citation source is missing")?;
    let text = source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .context("Parsed citation line is missing")?;
    let role = if prepared.discovery.contains(path) {
        "discovery"
    } else {
        "context only"
    };
    Ok(FindingEvidence {kind:FindingEvidence::UNSCORED_SOURCE_CITATION.into(),
        file_path:path.into(),line,snippet:prefix(text,256),
        rationale:format!("Supplied source excerpt ({role}); unscored. Source location is cited; interpretation remains unverified."),
        ..Default::default()})
}
