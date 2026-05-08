use super::*;

pub(crate) fn build_triage_outcome(
    analysis: &VulnAnalysis,
    outcome: &AgentLoopOutcome,
) -> TriageOutcome {
    let verdict = match (analysis.triggerable, analysis.confidence) {
        (true, c) if c >= 0.5 => TriageVerdict::TruePositive,
        (false, c) if c >= 0.7 => TriageVerdict::FalsePositive,
        _ => TriageVerdict::NeedsReview,
    };
    let rationale = if outcome.truncated {
        format!(
            "[deep-auditor truncated at {} steps] {}",
            outcome.steps_used, analysis.rationale
        )
    } else {
        analysis.rationale.clone()
    };
    TriageOutcome {
        verdict,
        confidence: analysis.confidence,
        rationale,
        cost_usd: outcome.cost_usd,
    }
}

pub fn save_evidence(db_path: &Path, finding_id: i64, evidence: &[EvidenceCitation]) -> Result<()> {
    if evidence.is_empty() {
        return Ok(());
    }
    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("could not open {} for evidence", db_path.display()))?;
    conn.execute_batch(
        r#"
        create table if not exists findings_evidence (
          id          integer primary key autoincrement,
          finding_id  integer not null,
          file        text    not null,
          start_line  integer not null,
          end_line    integer not null,
          note        text,
          kind        text,
          created_at  text    not null default (datetime('now'))
        );
        create index if not exists idx_findings_evidence_finding
          on findings_evidence(finding_id);
        "#,
    )?;
    let mut stmt = conn.prepare(
        "insert into findings_evidence(finding_id, file, start_line, end_line, note, kind)
         values (?, ?, ?, ?, ?, ?)",
    )?;
    for ev in evidence {
        stmt.execute(rusqlite::params![
            finding_id,
            ev.file,
            ev.start_line,
            ev.end_line,
            ev.note,
            ev.kind
        ])?;
    }
    Ok(())
}
