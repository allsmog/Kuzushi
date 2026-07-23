//! Import verified AFE crashes into the kuzushi findings store.
//!
//! Gate: only `verified == true` rows (the engine's grader reproduced the
//! crash) unless the caller explicitly opts unverified rows in at reduced
//! confidence. Severity is impact-derived (write/exec primitive → High,
//! everything else capped Medium). Fingerprints are seeded with the engine's
//! cross-harness `root_signature`, so re-fuzzing the same root cause — even
//! through a different harness — corroborates one identity instead of
//! duplicating findings. The import run id is content-addressed, making
//! re-imports replays (the ledger importer contract).

use super::crash_location::source_location;
use super::index_rows::{parse_and_fold, FoldedFinding};
use super::severity::fuzz_severity;
use crate::findings::{Finding, FindingEvidence, FindingStore, VulnSource};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use std::path::Path;

const INDEX_MAX_BYTES: usize = 64 * 1024 * 1024;
const RUN_LEDGER_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const FUZZ_TOOL_LABEL: &str = "fuzz";

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FuzzImportSummary {
    pub run_id: String,
    pub imported: usize,
    pub skipped_unverified: usize,
    pub skipped_rows: usize,
    pub source_path: String,
}

pub struct FuzzImportRequest<'a> {
    pub data_root: &'a Path,
    pub source_dir: &'a Path,
    pub target_filter: Option<&'a str>,
    pub include_unverified: bool,
}

pub fn import_afe_findings(
    workspace: &WorkspaceTarget,
    request: &FuzzImportRequest<'_>,
) -> Result<FuzzImportSummary> {
    let index_path = request.data_root.join("findings-index.jsonl");
    let body = crate::bounded_file::read_utf8_text(&index_path, INDEX_MAX_BYTES)
        .with_context(|| format!("Could not read AFE index {}", index_path.display()))?;
    let (folded, skipped_rows) = parse_and_fold(&body);
    let (eligible, skipped_unverified) = gate_rows(folded, request);
    let mut findings: Vec<Finding> = eligible
        .iter()
        .map(|row| build_fuzz_finding(row, request))
        .collect();
    stamp_import_grounding(workspace.root(), &mut findings);

    let store = FindingStore::open(workspace.findings_db_path())?;
    let run_id = fuzz_import_run_id(&findings);
    store.with_run_lifecycle(&run_id, workspace.root(), || {
        store.insert_findings(&run_id, &findings)?;
        Ok(((), findings.len()))
    })?;
    Ok(FuzzImportSummary {
        run_id,
        imported: findings.len(),
        skipped_unverified,
        skipped_rows,
        source_path: index_path.display().to_string(),
    })
}

/// Imported crashes are claims about the target tree like any other import;
/// stamp each with its grounding verdict (synthetic `fuzz/...` pseudo-paths
/// have line 0 and ground as `not_applicable`).
fn stamp_import_grounding(root: &Path, findings: &mut [Finding]) {
    let revision = crate::workspace::target_git_metadata(root).map(|metadata| metadata.sha);
    for finding in findings {
        finding.grounding = Some(crate::findings::ground_finding_location(
            root,
            &finding.file_path,
            finding.start_line,
            "",
            revision.as_deref(),
        ));
    }
}

fn gate_rows(
    folded: Vec<FoldedFinding>,
    request: &FuzzImportRequest<'_>,
) -> (Vec<FoldedFinding>, usize) {
    let mut eligible = Vec::new();
    let mut skipped_unverified = 0usize;
    for row in folded {
        if request
            .target_filter
            .is_some_and(|target| !target_matches(&row.recorded.target, target))
        {
            continue;
        }
        if !row.recorded.verified && !request.include_unverified {
            skipped_unverified += 1;
            continue;
        }
        eligible.push(row);
    }
    (eligible, skipped_unverified)
}

/// The engine records `target` either as the bare name or in project-path
/// form (`localfuzz/c/<name>`); a filter must match both spellings.
fn target_matches(recorded: &str, filter: &str) -> bool {
    recorded == filter || recorded.ends_with(&format!("/{filter}"))
}

/// Same folded content → same run id, so a re-import replays instead of
/// duplicating; new engine findings change the content and open a new run,
/// while unchanged rows still corroborate their existing identities.
fn fuzz_import_run_id(findings: &[Finding]) -> String {
    let fingerprints: Vec<&[u8]> = findings
        .iter()
        .map(|finding| finding.fingerprint.as_bytes())
        .collect();
    let hash = crate::identity::hash_parts("fuzz-import-run", &fingerprints);
    format!("fuzz-{}", &hash.as_str()[..16])
}

pub fn build_fuzz_finding(row: &FoldedFinding, request: &FuzzImportRequest<'_>) -> Finding {
    let recorded = &row.recorded;
    let location = locate(row, request);
    let (file_path, line) = location.unwrap_or_else(|| synthetic_location(row));
    let severity = fuzz_severity(row.effective_primitive(), row.write_evidence);
    let title = finding_title(row);
    let message = finding_message(row, &title);
    let mut finding = Finding::new_tool(
        FUZZ_TOOL_LABEL,
        rule_id(recorded.sanitizer.as_str(), recorded.error_token.as_str()),
        file_path.as_str(),
        line,
        None,
        severity,
        message,
    );
    finding.vuln_source = Some(VulnSource::Fuzzing);
    // Identity follows the engine's cross-harness crash signature: the same
    // root cause found again (any harness, any line drift) corroborates.
    finding.fingerprint = crate::identity::stable_fingerprint_for_tool(
        FUZZ_TOOL_LABEL,
        &format!("afe:{}", signature_seed(row)),
        &file_path,
        &finding.title,
        &finding.message,
    );
    finding.with_evidence(vec![crash_evidence(row, &file_path, line)])
}

/// Tier 1: the per-run ledger's full symbolized crash log. Tier 2: the
/// index excerpt (usually just the libFuzzer banner, but free to try).
fn locate(row: &FoldedFinding, request: &FuzzImportRequest<'_>) -> Option<(String, u32)> {
    let hint = request.source_dir.display().to_string();
    if let Some(output) = run_crash_output(request.data_root, row) {
        if let Some(location) = source_location(&output, &hint) {
            return Some(location);
        }
    }
    source_location(&row.recorded.crash_excerpt, &hint)
}

/// Fallback pseudo-path when no source frame can be recovered. Keyed by the
/// crash signature, not the harness, so the same root cause found through
/// two harnesses still folds to one identity.
fn synthetic_location(row: &FoldedFinding) -> (String, u32) {
    (
        format!("fuzz/{}/{}", row.recorded.target, signature_seed(row)),
        0,
    )
}

/// Identity seed priority: cross-harness root signature, then the per-target
/// dedupe signature, then the finding id (always present).
fn signature_seed(row: &FoldedFinding) -> &str {
    let recorded = &row.recorded;
    if !recorded.root_signature.is_empty() {
        &recorded.root_signature
    } else if !recorded.signature.is_empty() {
        &recorded.signature
    } else {
        &recorded.finding_id
    }
}

/// Full crash logs live in the engine's per-run ledger
/// (`runs/<run_id>/findings.jsonl`); the durable index only keeps a 240-char
/// excerpt. Run dirs are GC-pruned, so absence is normal, not an error.
fn run_crash_output(data_root: &Path, row: &FoldedFinding) -> Option<String> {
    let ledger = data_root
        .join("runs")
        .join(&row.recorded.run_id)
        .join("findings.jsonl");
    let body = crate::bounded_file::read_utf8_text(&ledger, RUN_LEDGER_MAX_BYTES).ok()?;
    for line in body.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("finding_id").and_then(serde_json::Value::as_str)
            == Some(row.recorded.finding_id.as_str())
        {
            return value
                .get("crash_output")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
        }
    }
    None
}

fn rule_id(sanitizer: &str, error_token: &str) -> String {
    let sanitizer = if sanitizer.is_empty() { "sanitizer" } else { sanitizer };
    format!("fuzz/{sanitizer}/{}", token_slug(error_token))
}

/// `"AddressSanitizer: heap-buffer-overflow"` → `heap-buffer-overflow`;
/// tokens without a sanitizer prefix slug as-is; empty → `crash`.
fn token_slug(error_token: &str) -> String {
    let short = error_token
        .rsplit(": ")
        .next()
        .unwrap_or(error_token)
        .trim();
    if short.is_empty() {
        return "crash".to_string();
    }
    short
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn finding_title(row: &FoldedFinding) -> String {
    let recorded = &row.recorded;
    let what = if recorded.error_token.is_empty() {
        "sanitizer crash"
    } else {
        recorded.error_token.as_str()
    };
    format!("{what} in {}", top_frame(row))
}

fn top_frame(row: &FoldedFinding) -> String {
    row.recorded
        .crash_state
        .first()
        .map(|frame| frame.split('(').next().unwrap_or(frame).trim().to_string())
        .filter(|frame| !frame.is_empty())
        .unwrap_or_else(|| row.recorded.harness.clone())
}

fn finding_message(row: &FoldedFinding, title: &str) -> String {
    let recorded = &row.recorded;
    let mut lines = vec![
        title.to_string(),
        format!(
            "target: {} · harness: {} · sanitizer: {}",
            recorded.target, recorded.harness, recorded.sanitizer
        ),
    ];
    if !recorded.crash_state.is_empty() {
        lines.push(format!("crash state: {}", recorded.crash_state.join(" <- ")));
    }
    if let Some(primitive) = row.effective_primitive() {
        lines.push(format!(
            "primitive: {primitive}{}",
            if row.write_evidence { " (write evidence confirmed)" } else { "" }
        ));
    }
    lines.push(format!(
        "reproductions: {} · verified: {}",
        recorded.reproductions, recorded.verified
    ));
    lines.push(format!(
        "afe finding: {} · afe run: {}",
        recorded.finding_id, recorded.run_id
    ));
    if let Some(pov) = pov_reference(row) {
        lines.push(pov);
    }
    lines.join("\n")
}

/// PoV bytes stay in the engine workspace; the finding carries a reference.
fn pov_reference(row: &FoldedFinding) -> Option<String> {
    let recorded = &row.recorded;
    let artifact = recorded.poc_artifact.as_deref()?;
    let mut reference = format!(
        "pov: runs/{}/artifacts/{artifact}",
        recorded.run_id
    );
    if let Some(sha) = &recorded.poc_sha256 {
        reference.push_str(&format!(" sha256={sha}"));
    }
    if let Some(size) = recorded.poc_size {
        reference.push_str(&format!(" size={size}"));
    }
    Some(reference)
}

fn crash_evidence(row: &FoldedFinding, file_path: &str, line: u32) -> FindingEvidence {
    let recorded = &row.recorded;
    FindingEvidence {
        kind: "reasoning".to_string(),
        file_path: file_path.to_string(),
        line,
        snippet: format!(
            "{} @ {}",
            recorded.error_token,
            recorded.crash_state.join(" <- ")
        ),
        rationale: crash_rationale(row),
        confidence: if recorded.verified { 90 } else { 40 },
        request_blob: None,
        response_blob: None,
    }
}

fn crash_rationale(row: &FoldedFinding) -> String {
    let mut parts = vec![format!(
        "Imported from agentic-fuzz-engine findings index; reproduced {} time(s) by the engine grader",
        row.recorded.reproductions
    )];
    if let Some(pov) = pov_reference(row) {
        parts.push(pov);
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn fixture_workspace() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        (temp, workspace)
    }

    fn recorded_line(finding_id: &str, verified: bool, primitive: &str) -> String {
        format!(
            r#"{{"event":"recorded","finding_id":"{finding_id}","run_id":"r1","target":"vhdx","harness":"vhdx_open","sanitizer":"address","error_token":"AddressSanitizer: heap-buffer-overflow","signature":"sig-{finding_id}","root_signature":"root-{finding_id}","crash_state":["ns::Parse(unsigned","ns::Open"],"primitive":"{primitive}","poc_artifact":"pov.bin","poc_sha256":"ab12","poc_size":18,"reproductions":3,"verified":{verified},"crash_excerpt":"INFO: Seed"}}"#
        )
    }

    fn write_afe_workspace(dir: &Path, index_body: &str, crash_output: Option<&str>) -> std::path::PathBuf {
        let data_root = dir.join("afe-data");
        std::fs::create_dir_all(data_root.join("runs/r1")).unwrap();
        std::fs::write(data_root.join("findings-index.jsonl"), index_body).unwrap();
        if let Some(output) = crash_output {
            let ledger_row = serde_json::json!({
                "finding_id": "finding-aa",
                "crash_output": output,
            });
            std::fs::write(
                data_root.join("runs/r1/findings.jsonl"),
                format!("{ledger_row}\n"),
            )
            .unwrap();
        }
        data_root
    }

    const CRASH_OUTPUT: &str = "#0 0x1 in __asan_memcpy /rt/asan/asan_interceptors.cpp:22:3\n\
        #1 0x2 in ns::Parse /repo/src/vhdx/parser.cpp:108:11\n";

    #[test]
    fn verified_write_finding_imports_high_with_repo_relative_location() {
        let (temp, workspace) = fixture_workspace();
        let body = format!(
            "{}\n{}\n",
            recorded_line("finding-aa", true, "read"),
            r#"{"event":"impact","finding_id":"finding-aa","detail":{"primitive":"write","write_evidence":"shadow write"}}"#,
        );
        let data_root = write_afe_workspace(temp.path(), &body, Some(CRASH_OUTPUT));
        let request = FuzzImportRequest {
            data_root: &data_root,
            source_dir: Path::new("/repo"),
            target_filter: None,
            include_unverified: false,
        };

        let summary = import_afe_findings(&workspace, &request).unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_unverified, 0);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.file_path, "src/vhdx/parser.cpp");
        assert_eq!(finding.start_line, 108);
        assert_eq!(finding.tool, FUZZ_TOOL_LABEL);
        assert_eq!(finding.vuln_source, Some(VulnSource::Fuzzing));
        assert_eq!(finding.rule_id, "fuzz/address/heap-buffer-overflow");
        assert!(finding.message.contains("pov: runs/r1/artifacts/pov.bin sha256=ab12"));
        assert_eq!(finding.evidence[0].confidence, 90);
    }

    #[test]
    fn unverified_rows_are_gated_and_read_primitives_cap_medium() {
        let (temp, workspace) = fixture_workspace();
        let body = format!(
            "{}\n{}\n",
            recorded_line("finding-aa", true, "read"),
            recorded_line("finding-bb", false, "write"),
        );
        let data_root = write_afe_workspace(temp.path(), &body, None);
        let request = FuzzImportRequest {
            data_root: &data_root,
            source_dir: Path::new("/repo"),
            target_filter: None,
            include_unverified: false,
        };

        let summary = import_afe_findings(&workspace, &request).unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_unverified, 1);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
        // No run ledger and a banner-only excerpt → signature-keyed
        // synthetic location.
        assert_eq!(findings[0].file_path, "fuzz/vhdx/root-finding-aa");
        assert_eq!(findings[0].start_line, 0);
    }

    #[test]
    fn reimport_replays_the_same_run_and_identity() {
        let (temp, workspace) = fixture_workspace();
        let body = format!("{}\n", recorded_line("finding-aa", true, "write"));
        let data_root = write_afe_workspace(temp.path(), &body, None);
        let request = FuzzImportRequest {
            data_root: &data_root,
            source_dir: Path::new("/repo"),
            target_filter: None,
            include_unverified: false,
        };

        let first = import_afe_findings(&workspace, &request).unwrap();
        let second = import_afe_findings(&workspace, &request).unwrap();

        assert_eq!(first.run_id, second.run_id);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        let identities: std::collections::BTreeSet<_> = findings
            .iter()
            .map(|f| f.identity_id.clone().unwrap_or_else(|| f.fingerprint.clone()))
            .collect();
        assert_eq!(identities.len(), 1, "one root cause must stay one identity");
    }

    #[test]
    fn cross_harness_duplicates_share_a_fingerprint_via_root_signature() {
        let row_a = recorded_line("finding-aa", true, "read");
        let row_b = row_a
            .replace("finding-aa", "finding-bb")
            .replace(r#""harness":"vhdx_open""#, r#""harness":"vhdx_meta""#)
            .replace("sig-finding-bb", "sig-other")
            .replace("root-finding-bb", "root-finding-aa");
        let (folded, _) = parse_and_fold(&format!("{row_a}\n{row_b}\n"));
        let request = FuzzImportRequest {
            data_root: Path::new("/nonexistent"),
            source_dir: Path::new("/repo"),
            target_filter: None,
            include_unverified: false,
        };

        let first = build_fuzz_finding(&folded[0], &request);
        let second = build_fuzz_finding(&folded[1], &request);

        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn target_filter_limits_the_import_and_accepts_project_path_form() {
        let (temp, workspace) = fixture_workspace();
        // The engine writes this spelling on per-target rounds (observed live).
        let other = recorded_line("finding-bb", true, "read").replace(
            r#""target":"vhdx""#,
            r#""target":"localfuzz/c/ntfs""#,
        );
        let body = format!("{}\n{other}\n", recorded_line("finding-aa", true, "read"));
        let data_root = write_afe_workspace(temp.path(), &body, None);
        let request = FuzzImportRequest {
            data_root: &data_root,
            source_dir: Path::new("/repo"),
            target_filter: Some("ntfs"),
            include_unverified: false,
        };

        let summary = import_afe_findings(&workspace, &request).unwrap();

        assert_eq!(summary.imported, 1, "project-path target spelling must match");
        assert!(target_matches("vhdx", "vhdx"));
        assert!(target_matches("localfuzz/c/vhdx", "vhdx"));
        assert!(!target_matches("localfuzz/c/vhdx_meta", "vhdx"));
    }

    #[test]
    fn token_slugs_and_rule_ids_are_stable() {
        assert_eq!(
            rule_id("address", "AddressSanitizer: heap-buffer-overflow"),
            "fuzz/address/heap-buffer-overflow"
        );
        assert_eq!(
            rule_id("address", "SEGV on unknown address"),
            "fuzz/address/segv-on-unknown-address"
        );
        assert_eq!(rule_id("", ""), "fuzz/sanitizer/crash");
    }
}
