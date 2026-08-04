//! Threat-model verification: check a document's claims against the target.
//!
//! Threat models arrive from three unverified paths — hand-dropped files,
//! `userEdited` documents, and version restores — and every consumer trusts
//! the file absolutely. Verification grounds the document: cited paths must
//! exist (with sane line numbers), the documented revision is compared to
//! HEAD (tri-state; a non-git target is not a failure), and coverage is
//! re-measured against fresh grounding surfaces. Dirty and non-Git targets
//! additionally require a matching content-tree identity. The verdict is
//! stamped on the document; consumers warn, they never drop.

use super::*;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

const MAX_CHECKED_PATH_REFS: usize = 500;
const MAX_LISTED_MISSING: usize = 12;
const VERIFY_MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const VERIFY_COVERAGE_MAX_ELEMENTS: usize = 40;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreatModelVerification {
    /// `verified` | `stale` (revision drift) | `failed` (evidence, links, or coverage).
    pub verdict: String,
    pub checked_paths: usize,
    pub missing_count: usize,
    /// Capped listing of missing/out-of-range citations for the operator.
    pub missing: Vec<String>,
    pub link_error_count: usize,
    /// Capped listing of missing, duplicate, or dangling DFD/context links.
    pub link_errors: Vec<String>,
    pub revision: RevisionCheck,
    pub coverage_considered: usize,
    pub coverage_gaps: usize,
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevisionCheck {
    pub documented: Option<String>,
    pub current: Option<String>,
    pub dirty: Option<bool>,
    /// None when either side is unknown (non-git target or unstamped doc).
    pub matches: Option<bool>,
}

pub fn verify_threat_model_document(
    document: &Value,
    target: &Path,
) -> Result<ThreatModelVerification> {
    let refs = cited_path_refs(document);
    let missing = missing_citations(target, &refs);
    let links = security_context_link_report(document);
    let revision = revision_check(document, target);
    let coverage = coverage_check(document, target)?;
    let verdict = if !missing.is_empty() || !links.is_complete() || !coverage.invariant_satisfied()
    {
        "failed"
    } else if revision.matches == Some(false) {
        "stale"
    } else {
        "verified"
    };
    Ok(ThreatModelVerification {
        verdict: verdict.to_string(),
        checked_paths: refs.len(),
        missing_count: missing.len(),
        missing: missing.into_iter().take(MAX_LISTED_MISSING).collect(),
        link_error_count: links.errors.len(),
        link_errors: links.errors.into_iter().take(MAX_LISTED_MISSING).collect(),
        revision,
        coverage_considered: coverage.considered,
        coverage_gaps: coverage.gaps.len(),
        verified_at_ms: epoch_ms_now(),
    })
}

/// Merge the verification block into the document (replacing any prior one).
pub fn stamp_verification(document: &mut Value, verification: &ThreatModelVerification) {
    if let Some(root) = document.as_object_mut() {
        root.insert(
            "verification".to_string(),
            serde_json::to_value(verification).unwrap_or(Value::Null),
        );
    }
}

/// Cheap consumption warning: revision drift or a stamped non-verified
/// verdict. Never blocks — consumers prepend it and proceed.
pub fn verification_warning(document: &Value, target: &Path) -> Option<String> {
    let revision = revision_check(document, target);
    if revision.matches == Some(false) {
        return Some(format!(
            "threat-model warning: document was built at revision {} but the target is now at {} — cited paths and lines may be stale (run threat-model:verify)",
            short_sha(revision.documented.as_deref()),
            short_sha(revision.current.as_deref()),
        ));
    }
    match document.pointer("/verification/verdict").and_then(Value::as_str) {
        Some("failed") => Some(
            "threat-model warning: the last verification failed evidence, security-context-link, or entry-point coverage checks — treat this model as incomplete or unreliable".to_string(),
        ),
        Some("stale") => Some(
            "threat-model warning: the last verification marked this document stale against the target revision".to_string(),
        ),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathRef {
    path: String,
    line: Option<u32>,
}

/// Path-like citations from the shapes producers actually emit: bare
/// `affectedFiles` lists, `evidence` strings with a trailing `:line`, and
/// any object carrying `filePath` (+ optional `startLine`) — which covers
/// threat evidence anchors and DFD anchors wherever they nest.
fn cited_path_refs(document: &Value) -> Vec<PathRef> {
    let mut refs = Vec::new();
    collect_path_refs(document, &mut refs);
    refs.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    refs.dedup();
    refs.truncate(MAX_CHECKED_PATH_REFS);
    refs
}

fn collect_path_refs(value: &Value, refs: &mut Vec<PathRef>) {
    match value {
        Value::Object(object) => collect_object_refs(object, refs),
        Value::Array(items) => {
            for item in items {
                collect_path_refs(item, refs);
            }
        }
        _ => {}
    }
}

fn collect_object_refs(object: &serde_json::Map<String, Value>, refs: &mut Vec<PathRef>) {
    if let Some(path) = object.get("filePath").and_then(Value::as_str) {
        let line = object
            .get("startLine")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        push_path_ref(refs, path, line);
    }
    for (key, child) in object {
        collect_keyed_refs(key, child, refs);
        collect_path_refs(child, refs);
    }
}

fn collect_keyed_refs(key: &str, child: &Value, refs: &mut Vec<PathRef>) {
    match key {
        "affectedFiles" | "affected_files" => {
            let paths = child.as_array().into_iter().flatten();
            for path in paths.filter_map(Value::as_str) {
                push_path_ref(refs, path, None);
            }
        }
        "evidence" => {
            if let Some(text) = child.as_str() {
                push_evidence_ref(refs, text);
            }
        }
        _ => {}
    }
}

fn push_evidence_ref(refs: &mut Vec<PathRef>, text: &str) {
    let (path, line) = match text.rsplit_once(':') {
        Some((path, digits))
            if digits.chars().all(|c| c.is_ascii_digit()) && !digits.is_empty() =>
        {
            (path, digits.parse().ok())
        }
        _ => (text, None),
    };
    if looks_like_path(path) {
        push_path_ref(refs, path, line);
    }
}

fn push_path_ref(refs: &mut Vec<PathRef>, path: &str, line: Option<u32>) {
    let path = path.trim();
    if path.is_empty() || path.contains("://") {
        return;
    }
    refs.push(PathRef {
        path: path.to_string(),
        line: line.filter(|line| *line > 0),
    });
}

/// Evidence strings are free text; only dotted relative paths count.
fn looks_like_path(candidate: &str) -> bool {
    let candidate = candidate.trim();
    !candidate.is_empty()
        && !candidate.contains(char::is_whitespace)
        && candidate.contains('.')
        && (candidate.contains('/') || Path::new(candidate).extension().is_some())
}

fn missing_citations(target: &Path, refs: &[PathRef]) -> Vec<String> {
    refs.iter()
        .filter_map(|path_ref| citation_problem(target, path_ref))
        .collect()
}

fn citation_problem(target: &Path, path_ref: &PathRef) -> Option<String> {
    let Some(resolved) = crate::findings::safe_target_path(target, &path_ref.path) else {
        return Some(format!("{} (escapes the target root)", path_ref.path));
    };
    // Directory citations are legitimate surface anchors (vendor trees,
    // workflow directories); only a wholly absent path is a failure.
    if !resolved.exists() {
        return Some(format!("{} (missing)", path_ref.path));
    }
    if !resolved.is_file() {
        return None;
    }
    let line = path_ref.line?;
    let source =
        crate::bounded_file::read_utf8_text_within(target, &resolved, VERIFY_MAX_FILE_BYTES)
            .ok()?;
    let count = source.lines().count() as u32;
    (line > count).then(|| format!("{}:{line} (file has {count} lines)", path_ref.path))
}

fn revision_check(document: &Value, target: &Path) -> RevisionCheck {
    let documented = document
        .pointer("/provenance/revision")
        .and_then(Value::as_str)
        .map(str::to_string);
    let metadata = crate::workspace::target_git_metadata(target);
    let current = metadata.as_ref().map(|meta| meta.sha.clone());
    let matches = match (documented.as_deref(), current.as_deref()) {
        (Some(documented), Some(current)) => Some(documented == current),
        _ => None,
    };
    RevisionCheck {
        documented,
        current,
        dirty: metadata.map(|meta| meta.dirty),
        matches,
    }
}

fn coverage_check(document: &Value, target: &Path) -> Result<CoverageReport> {
    let surfaces = verification_grounding_surfaces(document, target)?;
    Ok(check_coverage(document, &surfaces))
}

struct CatalogCoverageReceipt {
    status: String,
    sha256: Option<String>,
    snapshot_timestamp: Option<u64>,
    context_sha256: Option<String>,
    tree_hash: Option<String>,
    revision: Option<String>,
    revision_dirty: Option<bool>,
}

impl CatalogCoverageReceipt {
    fn is_unavailable(&self) -> bool {
        matches!(self.status.as_str(), "disabled" | "missing")
    }
}

fn verification_grounding_surfaces(
    document: &Value,
    target: &Path,
) -> Result<Vec<crate::attack_surface::AttackSurface>> {
    let receipt = catalog_coverage_receipt(document)?;
    let catalog = crate::capabilities::entry_points::resolve_entry_point_catalog_for_verification(
        target,
    )?;
    if let Some(catalog) = catalog {
        if let Some(receipt) = receipt.as_ref().filter(|receipt| !receipt.is_unavailable()) {
            authenticate_receipt_catalog(receipt, &catalog)?;
        }
        return full_catalog_verification_surfaces(target, &catalog);
    }
    anyhow::ensure!(
        receipt.as_ref().is_none_or(CatalogCoverageReceipt::is_unavailable),
        "catalog-backed threat model cannot be verified without its authenticated entry-point catalog"
    );
    validate_unbacked_source(document, target, receipt.as_ref())?;
    noncatalog_verification_surfaces(target)
}

fn catalog_coverage_receipt(document: &Value) -> Result<Option<CatalogCoverageReceipt>> {
    let Some(receipt) = document.pointer("/provenance/entryPointCatalog") else {
        return Ok(None);
    };
    let status = required_receipt_text(receipt, "status")?;
    let unavailable = matches!(status, "disabled" | "missing");
    if unavailable {
        validate_unavailable_receipt(receipt)?;
    }
    anyhow::ensure!(
        unavailable || matches!(status, "current" | "refreshed" | "explicit"),
        "unsupported entry-point catalog receipt status {status:?}"
    );
    let selection_policy = required_receipt_text(receipt, "selectionPolicy")?;
    validate_selection_policy(selection_policy)?;
    let parsed = CatalogCoverageReceipt {
        status: status.to_string(),
        sha256: optional_receipt_text(receipt, "sha256", unavailable)?,
        snapshot_timestamp: optional_receipt_u64(receipt, "snapshotTimestamp", unavailable)?,
        context_sha256: optional_receipt_text(receipt, "contextSha256", unavailable)?,
        tree_hash: nullable_receipt_text(receipt, "treeHash")?,
        revision: nullable_receipt_text(receipt, "revision")?,
        revision_dirty: nullable_receipt_bool(receipt, "revisionDirty")?,
    };
    Ok(Some(parsed))
}

fn validate_selection_policy(policy: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(
            policy,
            crate::capabilities::entry_points::ENTRY_POINT_SELECTION_POLICY
                | DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY
        ),
        "entry-point catalog selection policy is unsupported"
    );
    Ok(())
}

fn validate_unavailable_receipt(receipt: &Value) -> Result<()> {
    anyhow::ensure!(
        receipt.get("sha256").is_none_or(Value::is_null)
            && receipt.get("snapshotTimestamp").is_none_or(Value::is_null)
            && receipt.get("contextSha256").is_none_or(Value::is_null)
            && required_receipt_usize(receipt, "records")? == 0
            && required_receipt_usize(receipt, "recordsSelected")? == 0,
        "unavailable entry-point catalog receipt claims catalog evidence"
    );
    Ok(())
}

fn authenticate_receipt_catalog(
    receipt: &CatalogCoverageReceipt,
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
) -> Result<()> {
    anyhow::ensure!(
        receipt.sha256.as_deref() == Some(catalog.provenance.sha256.as_str())
            && receipt.snapshot_timestamp == Some(catalog.snapshot_timestamp)
            && receipt.context_sha256.as_deref()
                == Some(catalog.provenance.context_snapshot_sha256.as_str())
            && receipt.tree_hash == catalog.provenance.context_snapshot_tree_hash
            && receipt.revision == catalog.provenance.revision
            && receipt.revision_dirty == catalog.provenance.revision_dirty,
        "authenticated entry-point catalog does not match the threat-model receipt"
    );
    Ok(())
}

fn full_catalog_verification_surfaces(
    target: &Path,
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
) -> Result<Vec<crate::attack_surface::AttackSurface>> {
    let mut surfaces = catalog
        .entry_points
        .iter()
        .map(|entry| entry.surface.clone())
        .collect::<Vec<_>>();
    let supplemental = noncatalog_verification_surfaces(target)?;
    append_unique_verification_surfaces(&mut surfaces, supplemental);
    Ok(surfaces)
}

fn noncatalog_verification_surfaces(
    target: &Path,
) -> Result<Vec<crate::attack_surface::AttackSurface>> {
    let mut surfaces = grounding_surfaces(target, VERIFY_COVERAGE_MAX_ELEMENTS)?;
    let map = crate::attack_surface::build_attack_surface_map(target)
        .context("threat-model verification: attack-surface map failed")?;
    let deterministic = deterministic_threat_surfaces(
        &map.surfaces,
        VERIFY_COVERAGE_MAX_ELEMENTS,
    );
    append_unique_verification_surfaces(&mut surfaces, deterministic);
    Ok(surfaces)
}

fn append_unique_verification_surfaces(
    surfaces: &mut Vec<crate::attack_surface::AttackSurface>,
    supplemental: Vec<crate::attack_surface::AttackSurface>,
) {
    let mut ids = surfaces
        .iter()
        .map(|surface| surface.id.clone())
        .collect::<BTreeSet<_>>();
    surfaces.extend(
        supplemental
            .into_iter()
            .filter(|surface| ids.insert(surface.id.clone())),
    );
}

fn validate_unbacked_source(
    document: &Value,
    target: &Path,
    receipt: Option<&CatalogCoverageReceipt>,
) -> Result<()> {
    let current = crate::workspace::target_git_metadata(target);
    if current.as_ref().is_some_and(|git| !git.dirty) {
        return Ok(());
    }
    let tree_hash = receipt
        .and_then(|receipt| receipt.tree_hash.as_deref())
        .or_else(|| document.pointer("/provenance/treeHash").and_then(Value::as_str))
        .context(
            "dirty or non-Git threat-model verification requires a bound provenance treeHash",
        )?;
    let actual = crate::incremental_index::current_workspace_tree_hash(target)
        .context("Could not authenticate the current target tree")?;
    anyhow::ensure!(tree_hash == actual, "threat-model source tree is stale");
    validate_unbacked_git_identity(document, receipt, current.as_ref())
}

fn validate_unbacked_git_identity(
    document: &Value,
    receipt: Option<&CatalogCoverageReceipt>,
    current: Option<&crate::run_artifacts::RunTargetGitMetadata>,
) -> Result<()> {
    let revision = receipt
        .and_then(|receipt| receipt.revision.as_deref())
        .or_else(|| document.pointer("/provenance/revision").and_then(Value::as_str));
    let dirty = receipt
        .and_then(|receipt| receipt.revision_dirty)
        .or_else(|| document.pointer("/provenance/revisionDirty").and_then(Value::as_bool));
    let Some(current) = current else {
        anyhow::ensure!(
            revision.is_none() && dirty.is_none(),
            "threat-model repository identity is stale"
        );
        return Ok(());
    };
    anyhow::ensure!(
        revision == Some(current.sha.as_str()) && dirty == Some(current.dirty),
        "threat-model repository identity is stale"
    );
    Ok(())
}

fn required_receipt_text<'a>(receipt: &'a Value, field: &str) -> Result<&'a str> {
    receipt
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("entry-point catalog receipt has no {field}"))
}

fn required_receipt_u64(receipt: &Value, field: &str) -> Result<u64> {
    receipt
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("entry-point catalog receipt has no numeric {field}"))
}

fn optional_receipt_text(
    receipt: &Value,
    field: &str,
    unavailable: bool,
) -> Result<Option<String>> {
    if unavailable {
        return Ok(None);
    }
    Ok(Some(required_receipt_text(receipt, field)?.to_string()))
}

fn optional_receipt_u64(receipt: &Value, field: &str, unavailable: bool) -> Result<Option<u64>> {
    if unavailable {
        return Ok(None);
    }
    Ok(Some(required_receipt_u64(receipt, field)?))
}

fn nullable_receipt_text(receipt: &Value, field: &str) -> Result<Option<String>> {
    match receipt.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.to_string())),
        _ => anyhow::bail!("entry-point catalog receipt has invalid {field}"),
    }
}

fn nullable_receipt_bool(receipt: &Value, field: &str) -> Result<Option<bool>> {
    match receipt.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        _ => anyhow::bail!("entry-point catalog receipt has invalid {field}"),
    }
}

fn required_receipt_usize(receipt: &Value, field: &str) -> Result<usize> {
    usize::try_from(required_receipt_u64(receipt, field)?)
        .with_context(|| format!("entry-point catalog receipt {field} exceeds host limits"))
}

fn short_sha(sha: Option<&str>) -> String {
    sha.map(|sha| sha.chars().take(12).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

fn epoch_ms_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod verify_tests;
