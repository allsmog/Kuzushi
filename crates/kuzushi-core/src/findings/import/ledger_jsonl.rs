//! External findings-ledger backfill importer.
//!
//! Parses a JSONL export from another scanner or triage pipeline into
//! canonical `Finding` rows so kuzushi's dedupe/triage/verify workflows
//! see prior history. Rows are tolerant-parsed: a row missing its file
//! or title is counted as skipped instead of failing the import.

use crate::findings::{
    ground_finding_location, Finding, FindingEvidence, FindingStore, GroundingStatus, Severity,
};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const LEDGER_IMPORT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Outcome of one ledger import call.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LedgerImportSummary {
    pub run_id: String,
    pub imported: usize,
    pub skipped_rows: usize,
    pub source_path: String,
    pub tool: String,
}

/// One tolerant external-ledger row. Fields are extracted by key
/// priority rather than serde aliases because real exports carry both
/// a field and its alias in the same row (`file` + `_file`), which
/// serde rejects as a duplicate field.
#[derive(Debug, Default)]
struct LedgerRow {
    file: String,
    line: u32,
    title: String,
    severity: String,
    cwe: String,
    verdict: String,
    precondition: String,
    trust_boundary: String,
    origin: String,
}

/// Parse a findings-ledger JSONL file and persist each valid row as a
/// `Finding` under one import run. `tool_label` becomes `Finding.tool`
/// so backfilled history stays distinguishable from live scan output.
///
/// The run id is content-addressed (`ledger_import_run_id`), which makes the
/// import idempotent: a re-import after a killed/timeout-aborted partial
/// import replays onto the same run and projected finding ids, healing the
/// partial state instead of duplicating every row under a fresh run.
pub fn import_ledger_jsonl(
    workspace: &WorkspaceTarget,
    path: &Path,
    tool_label: &str,
) -> Result<LedgerImportSummary> {
    let body = crate::bounded_file::read_utf8_text(path, LEDGER_IMPORT_MAX_BYTES)
        .with_context(|| format!("Could not read findings ledger {}", path.display()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let run_id = ledger_import_run_id(tool_label, &body);
    let (imported, skipped) = import_or_replay(&store, workspace, &run_id, &body, tool_label)?;
    Ok(LedgerImportSummary {
        run_id,
        imported,
        skipped_rows: skipped,
        source_path: path.display().to_string(),
        tool: tool_label.to_string(),
    })
}

fn import_or_replay(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    run_id: &str,
    body: &str,
    tool_label: &str,
) -> Result<(usize, usize)> {
    if store.run_status(run_id)?.as_deref() == Some("completed") {
        return Ok(ledger_row_counts(body));
    }
    let grounding = LedgerGrounding::for_target(workspace.root());
    store.with_run_lifecycle(run_id, workspace.root(), || {
        persist_ledger_rows(store, run_id, body, tool_label, &grounding)
    })
}

fn ledger_row_counts(body: &str) -> (usize, usize) {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .fold((0, 0), |(valid, skipped), line| {
            match parse_ledger_row(line) {
                Some(_) => (valid + 1, skipped),
                None => (valid, skipped + 1),
            }
        })
}

/// Deterministic, content-addressed import run id. Same ledger bytes + tool
/// label → same run id, so re-imports are replays, not new runs.
pub(crate) fn ledger_import_run_id(tool_label: &str, body: &str) -> String {
    let hash = crate::identity::hash_parts(
        "ledger-import-run",
        &[tool_label.as_bytes(), body.as_bytes()],
    );
    format!("ledger-{}", &hash.as_str()[..16])
}

/// Recognize the reserved content-addressed import namespace, which records
/// external history and does not establish a local discovery scan.
pub fn is_ledger_import_run_id(value: &str) -> bool {
    value.strip_prefix("ledger-").is_some_and(|suffix| {
        suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn persist_ledger_rows(
    store: &FindingStore,
    run_id: &str,
    body: &str,
    tool_label: &str,
    grounding: &LedgerGrounding,
) -> Result<((usize, usize), usize)> {
    let mut findings = Vec::new();
    let mut skipped = 0usize;
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match parse_ledger_row(line) {
            Some(row) => findings.push(build_ledger_finding(&row, tool_label, grounding)),
            None => skipped += 1,
        }
    }
    // One batched insert so the storage writer session (and its event-log
    // chain verification) opens once per import, not once per row — per-row
    // sessions made large imports quadratic in ledger history.
    store.insert_findings(run_id, &findings)?;
    let imported = findings.len();
    Ok(((imported, skipped), imported))
}

fn parse_ledger_row(line: &str) -> Option<LedgerRow> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;
    let row = LedgerRow {
        file: first_string(object, &["file", "path", "file_path", "_file"]),
        line: first_u32(object, &["line", "start_line", "_line"]),
        title: first_string(object, &["title", "message", "summary"]),
        severity: first_string(object, &["severity", "tier"]),
        cwe: first_string(object, &["cwe", "class", "rule", "rule_id"]),
        verdict: first_string(object, &["verdict", "triage_verdict"]),
        precondition: first_string(object, &["precondition"]),
        trust_boundary: first_string(object, &["trust_boundary"]),
        origin: first_string(object, &["origin", "shard"]),
    };
    if row.file.is_empty() || row.title.is_empty() {
        return None;
    }
    Some(row)
}

fn first_string(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> String {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .filter_map(serde_json::Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn first_u32(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> u32 {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(ledger_line_number)
        .unwrap_or(0)
}

fn ledger_line_number(value: &serde_json::Value) -> Option<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).ok();
    }
    value.as_str()?.trim().parse().ok()
}

/// Grounding context computed once per import: the target root and its
/// current HEAD (None outside a git checkout).
pub(crate) struct LedgerGrounding {
    root: PathBuf,
    revision: Option<String>,
}

impl LedgerGrounding {
    pub(crate) fn for_target(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            revision: crate::workspace::target_git_metadata(root).map(|metadata| metadata.sha),
        }
    }

    fn ground(&self, row: &LedgerRow) -> (GroundingStatus, Option<String>) {
        let status = ground_finding_location(
            &self.root,
            &row.file,
            row.line,
            "",
            self.revision.as_deref(),
        );
        let cited_line = status
            .is_grounded()
            .then(|| disk_line_text(&self.root, &row.file, row.line))
            .flatten();
        (status, cited_line)
    }
}

fn disk_line_text(root: &Path, file: &str, line: u32) -> Option<String> {
    let path = crate::findings::domain::safe_target_path(root, file)?;
    let source = crate::bounded_file::read_utf8_text_within(root, &path, 8 * 1024 * 1024).ok()?;
    source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .map(|text| text.trim_end().to_string())
        .filter(|text| !text.trim().is_empty())
}

fn build_ledger_finding(row: &LedgerRow, tool_label: &str, grounding: &LedgerGrounding) -> Finding {
    let mut finding = Finding::new_tool(
        tool_label,
        ledger_rule_id(row),
        row.file.as_str(),
        row.line,
        None,
        contracted_severity(row),
        ledger_message(row),
    );
    // Tool fingerprints hash only (tool, rule_id, file) so scanner findings
    // survive line shifts — but ledger rows are point facts: distinct sinks
    // of the same class in one file (nine `informix_utils.cpp` corpus rows)
    // must stay distinct findings. Qualify the fingerprint seed with the
    // line; re-importing the same row still lands on the same fingerprint.
    finding.fingerprint = crate::identity::stable_fingerprint_for_tool(
        tool_label,
        &format!("{}#L{}", ledger_rule_id(row), row.line),
        row.file.as_str(),
        &finding.title,
        &finding.message,
    );
    let (status, cited_line) = grounding.ground(row);
    // The annotation lands after the fingerprint seed is fixed: grounding
    // varies with the checked-out revision and must never fork identity.
    if let Some(note) = grounding_annotation(&status) {
        finding.message.push_str(&format!("\n{note}"));
    }
    let mut evidence = vec![ledger_evidence(row)];
    if let Some(text) = cited_line {
        evidence.push(citation_evidence(row, text));
    }
    finding.grounding = Some(status);
    finding.with_evidence(evidence)
}

/// One message annotation line for stale anchors (severity-ceiling
/// convention: recorded mechanically, never re-litigated in prompts).
fn grounding_annotation(status: &GroundingStatus) -> Option<String> {
    let revision = |revision: &Option<String>| {
        revision
            .as_deref()
            .map(|sha| sha.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "non-git target".to_string())
    };
    match status {
        GroundingStatus::Grounded { .. } | GroundingStatus::NotApplicable => None,
        GroundingStatus::Unavailable { reason } => {
            Some(format!("grounding: unavailable ({reason})"))
        }
        GroundingStatus::LineDrift {
            nearest_line,
            revision: rev,
        } => Some(format!(
            "grounding: line_drift (nearest line {nearest_line}) at {}",
            revision(rev)
        )),
        GroundingStatus::FileMissing { revision: rev } => {
            Some(format!("grounding: file_missing at {}", revision(rev)))
        }
    }
}

/// Grounded rows carry a real disk citation, so the store's
/// disk-verification pass applies to imported evidence exactly as it does
/// to native scanner evidence.
fn citation_evidence(row: &LedgerRow, cited_line: String) -> FindingEvidence {
    FindingEvidence {
        kind: "code".to_string(),
        file_path: row.file.trim().to_string(),
        line: row.line,
        snippet: cited_line,
        rationale: "Import grounding: cited line read from the target tree".to_string(),
        confidence: ledger_confidence(&row.verdict),
        request_blob: None,
        response_blob: None,
    }
}

/// The title stays the first message line; the precondition chain
/// rides in the body so ledger exports keep it (evidence rationale is
/// summarised to counts on export).
///
/// The trailing `location:` line keeps the point-fact location visible in
/// rendered views (identity itself is line-qualified in
/// `build_ledger_finding` — fingerprints ignore message text).
fn ledger_message(row: &LedgerRow) -> String {
    let mut message = row.title.clone();
    for (label, value) in [
        ("precondition", &row.precondition),
        ("trust boundary", &row.trust_boundary),
    ] {
        if !value.is_empty() {
            message.push_str(&format!("\n{label}: {value}"));
        }
    }
    message.push_str(&format!("\nlocation: {}:{}", row.file, row.line));
    message
}

/// Rule id carries the exporter's class label; when the row names a
/// CWE anywhere, `Finding::new_tool` extracts it for the dedup key.
fn ledger_rule_id(row: &LedgerRow) -> String {
    let class = row.cwe.trim();
    if class.is_empty() {
        "imported-ledger".to_string()
    } else {
        class.to_string()
    }
}

/// Ingest-contract chokepoint: the claimed tier is capped mechanically by
/// the row's precondition ceiling (`findings::ingest_contract`). The cap is
/// code, not a review opinion.
fn contracted_severity(row: &LedgerRow) -> Severity {
    let claimed = ledger_severity(&row.severity);
    let precondition = crate::findings::ingest_contract::Precondition::parse(&row.precondition);
    crate::findings::ingest_contract::enforce_severity_ceiling(claimed, precondition).severity
}

/// External P-tier severity labels (P0..P3) map onto kuzushi severities; anything else
/// goes through the shared label parser (critical/high/... strings).
fn ledger_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_uppercase().as_str() {
        "P0" => Severity::Critical,
        "P1" => Severity::High,
        "P2" => Severity::Medium,
        "P3" => Severity::Low,
        other => Severity::from_label(other),
    }
}

/// Ledger rows carry triage prose, not verifiable code citations, so
/// the evidence kind is `reasoning` — claiming a citation would be
/// downgraded by the store's disk-verification pass anyway.
fn ledger_evidence(row: &LedgerRow) -> FindingEvidence {
    FindingEvidence {
        kind: "reasoning".to_string(),
        file_path: row.file.trim().to_string(),
        line: row.line,
        // The evidence snippet feeds the identity key (it wins over the
        // message text locator). Ledger rows are point facts: qualify the
        // snippet with the location so same-titled sinks at different
        // lines keep distinct identities, while re-imports of the same
        // row still corroborate.
        snippet: format!("{} @ {}:{}", row.title.trim(), row.file.trim(), row.line),
        rationale: ledger_rationale(row),
        confidence: ledger_confidence(&row.verdict),
        request_blob: None,
        response_blob: None,
    }
}

fn ledger_rationale(row: &LedgerRow) -> String {
    let mut parts = vec!["Imported from external findings ledger".to_string()];
    for (label, value) in [
        ("verdict", &row.verdict),
        ("precondition", &row.precondition),
        ("trust boundary", &row.trust_boundary),
        ("origin", &row.origin),
    ] {
        if !value.trim().is_empty() {
            parts.push(format!("{label}: {}", value.trim()));
        }
    }
    parts.join("; ")
}

/// Verified prior true positives arrive with higher confidence than
/// untriaged rows so review ordering reflects the source pipeline.
fn ledger_confidence(verdict: &str) -> u8 {
    match verdict.trim().to_ascii_uppercase().as_str() {
        "TRUE_POSITIVE" | "VALIDATED" | "CONFIRMED" => 90, // External input validation compatibility.
        "FALSE_POSITIVE" | "REFUTED" | "REJECTED" => 10,
        _ => 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_workspace() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        (temp, workspace)
    }

    fn write_ledger(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("ledger.jsonl");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn imports_p_tier_rows_and_skips_incomplete_lines() {
        let (temp, workspace) = fixture_workspace();
        let ledger = write_ledger(
            temp.path(),
            concat!(
                r#"{"file":"src/a.cpp","line":10,"title":"OOB write (CWE-787)","severity":"P0","class":"mem-oob-write","verdict":"TRUE_POSITIVE"}"#,
                "\n",
                r#"{"file":"","title":"no file"}"#,
                "\n",
                "not-json\n",
                r#"{"file":"src/b.cpp","line":5,"title":"missing authz","tier":"P2"}"#,
                "\n",
            ),
        );

        let summary = import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();

        assert_eq!(summary.imported, 2);
        assert_eq!(summary.skipped_rows, 2);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(100).unwrap();
        assert_eq!(findings.len(), 2);
        let critical = findings
            .iter()
            .find(|f| f.file_path == "src/a.cpp")
            .unwrap();
        assert_eq!(critical.severity, Severity::Critical);
        assert_eq!(critical.tool, "external-corpus");
        assert!(critical.dedup_key.is_some(), "CWE row must gain dedup key");
        assert_eq!(critical.evidence.len(), 1);
        assert_eq!(critical.evidence[0].confidence, 90);
        let medium = findings
            .iter()
            .find(|f| f.file_path == "src/b.cpp")
            .unwrap();
        assert_eq!(medium.severity, Severity::Medium);
    }

    #[test]
    fn same_title_rows_at_different_lines_stay_distinct_findings() {
        let (temp, workspace) = fixture_workspace();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        let mut source = vec![""; 717];
        source[146] = "popen(first_command);";
        source[716] = "popen(second_command);";
        std::fs::write(temp.path().join("src/informix.cpp"), source.join("\n")).unwrap();
        let ledger = write_ledger(
            temp.path(),
            concat!(
                r#"{"file":"src/informix.cpp","line":147,"title":"popen injection","severity":"P1"}"#,
                "\n",
                r#"{"file":"src/informix.cpp","line":717,"title":"popen injection","severity":"P1"}"#,
                "\n",
            ),
        );

        let summary = import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();

        assert_eq!(summary.imported, 2);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(100).unwrap();
        assert_eq!(findings.len(), 2, "distinct sinks must not conflate");
        assert_ne!(
            findings[0].fingerprint, findings[1].fingerprint,
            "the location line must make each row's fingerprint distinct"
        );
    }

    #[test]
    fn reimport_corroborates_instead_of_duplicating_identities() {
        let (temp, workspace) = fixture_workspace();
        let ledger = write_ledger(
            temp.path(),
            concat!(
                r#"{"file":"src/a.cpp","line":10,"title":"OOB write (CWE-787)","severity":"P0"}"#,
                "\n",
            ),
        );

        import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();
        import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(100).unwrap();
        let identities: std::collections::BTreeSet<_> = findings
            .iter()
            .map(|f| {
                f.identity_id
                    .clone()
                    .unwrap_or_else(|| f.fingerprint.clone())
            })
            .collect();
        assert_eq!(identities.len(), 1, "same row must map to one identity");
    }

    #[test]
    fn reimport_after_a_killed_partial_import_heals_instead_of_duplicating() {
        let (temp, workspace) = fixture_workspace();
        let row_a =
            r#"{"file":"src/a.cpp","line":10,"title":"OOB write (CWE-787)","severity":"P0"}"#;
        let row_b = r#"{"file":"src/b.cpp","line":5,"title":"missing authz","severity":"P2"}"#;
        let body = format!("{row_a}\n{row_b}\n");
        let ledger = write_ledger(temp.path(), &body);

        // Simulate a timeout-killed import: the run started and persisted
        // only the first row, then died before finishing its lifecycle.
        let run_id = ledger_import_run_id("external-corpus", &body);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started(&run_id, workspace.root(), "running")
            .unwrap();
        let partial = build_ledger_finding(
            &parse_ledger_row(row_a).unwrap(),
            "external-corpus",
            &LedgerGrounding::for_target(workspace.root()),
        );
        store.insert_findings(&run_id, &[partial]).unwrap();
        drop(store);

        let summary = import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();

        assert_eq!(summary.run_id, run_id, "re-import must replay the same run");
        assert_eq!(summary.imported, 2);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(100).unwrap();
        assert_eq!(
            findings.len(),
            2,
            "the partial row must be healed in place, not duplicated: {:#?}",
            findings
                .iter()
                .map(|f| (&f.file_path, &f.scan_id))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn grounded_rows_gain_verified_citation_evidence() {
        let (temp, workspace) = fixture_workspace();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/real.cpp"),
            "int main() {\n    system(user_input);\n    return 0;\n}\n",
        )
        .unwrap();
        let ledger = write_ledger(
            temp.path(),
            concat!(
                r#"{"file":"src/real.cpp","line":2,"title":"command injection (CWE-78)","severity":"P1"}"#,
                "\n",
            ),
        );

        import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        assert!(
            matches!(finding.grounding, Some(GroundingStatus::Grounded { .. })),
            "grounding: {:?}",
            finding.grounding
        );
        assert!(
            !finding.message.contains("grounding:"),
            "grounded rows carry no stale-anchor annotation"
        );
        let citation = finding
            .evidence
            .iter()
            .find(|item| item.snippet.contains("system(user_input)"))
            .expect("citation evidence with the real disk line");
        assert_eq!(
            citation.kind, "code",
            "the disk-verification pass must keep the citation, not downgrade it"
        );
    }

    #[test]
    fn missing_file_rows_are_annotated_but_still_imported() {
        let (temp, workspace) = fixture_workspace();
        let ledger = write_ledger(
            temp.path(),
            concat!(
                r#"{"file":"src/gone.cpp","line":9,"title":"stale citation (CWE-787)","severity":"P1"}"#,
                "\n",
            ),
        );

        let summary = import_ledger_jsonl(&workspace, &ledger, "external-corpus").unwrap();

        assert_eq!(summary.imported, 1, "grounding never drops rows");
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        assert!(
            matches!(finding.grounding, Some(GroundingStatus::FileMissing { .. })),
            "grounding: {:?}",
            finding.grounding
        );
        assert!(finding.message.contains("grounding: file_missing at"));
        assert_eq!(finding.evidence.len(), 1, "no fabricated citation");
    }

    #[test]
    fn corpus_alias_fields_parse() {
        let row = parse_ledger_row(
            r#"{"_file":"src/x.cpp","_line":7,"summary":"t","tier":"P1","rule":"authz-missing","triage_verdict":"FALSE_POSITIVE"}"#,
        )
        .unwrap();
        assert_eq!(row.file, "src/x.cpp");
        assert_eq!(row.line, 7);
        assert_eq!(ledger_severity(&row.severity), Severity::High);
        assert_eq!(ledger_confidence(&row.verdict), 10);
    }

    #[test]
    fn precondition_chain_rides_in_the_message_body() {
        let row = parse_ledger_row(
            r#"{"file":"src/a.cpp","line":1,"title":"OOB write","precondition":"paired-peer","trust_boundary":"peer -> /sd/** write"}"#,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let finding = build_ledger_finding(
            &row,
            "external-corpus",
            &LedgerGrounding::for_target(temp.path()),
        );
        assert_eq!(finding.title, "OOB write");
        assert!(finding.message.contains("precondition: paired-peer"));
        assert!(finding
            .message
            .contains("trust boundary: peer -> /sd/** write"));
    }

    #[test]
    fn rows_with_both_field_and_alias_keys_still_parse() {
        // Real triage-corpus rows carry `file` AND `_file` (and
        // `line` + `_line`); the primary key must win, not error.
        let row = parse_ledger_row(
            r#"{"file":"src/real.cpp","_file":"src/dup.cpp","line":42,"_line":42,"title":"t","severity":"P1","class":"authz-missing","verdict":"TRUE_POSITIVE","shard":"cpp-tb-x"}"#,
        )
        .unwrap();
        assert_eq!(row.file, "src/real.cpp");
        assert_eq!(row.line, 42);
        assert_eq!(row.origin, "cpp-tb-x");
    }
}
