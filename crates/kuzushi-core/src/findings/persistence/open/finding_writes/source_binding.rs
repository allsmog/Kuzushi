//! Authenticate observation source once, then insert without reading the live tree.
use super::*;
use crate::content_store::{object_hash, ObjectKind};
mod snapshot;
use crate::identity::Blake3Hash;
use crate::workspace::{ReviewSourceTree, WorkspaceTarget};
pub(crate) use snapshot::FindingSourceSnapshot;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct CapturedFindingSources {
    root: PathBuf,
    snapshot: SnapshotWrite,
    files: BTreeMap<String, CapturedFile>,
}

struct CapturedFile {
    text: String,
    supplied_lines: usize,
    hash: Blake3Hash,
    storage_path: PathBuf,
}

impl FindingStore {
    #[cfg(test)]
    pub(crate) fn capture_finding_sources(
        &self,
        snapshot_hash: &str,
        tree_hash: &str,
        supplied: &BTreeMap<String, String>,
        findings: &[Finding],
        maximum: usize,
        canceled: &dyn Fn() -> bool,
    ) -> Result<CapturedFindingSources> {
        let target = self
            .v3_workspace_root()
            .context("Source binding requires workspace storage")?;
        self.prepare_finding_source_snapshot(&target, snapshot_hash, tree_hash)?
            .capture(supplied, findings, maximum, canceled)
    }

    pub(crate) fn insert_unbound_native_finding(
        &self,
        run_id: &str,
        finding: &Finding,
    ) -> Result<i64> {
        let mut writer = self.storage_writer_session()?;
        self.insert_finding_at_source(
            run_id,
            finding,
            &mut writer,
            ObservationSourceWrite::Unavailable,
        )
    }

    pub(crate) fn insert_finding_with_sources(
        &self,
        run_id: &str,
        finding: &Finding,
        source: &CapturedFindingSources,
    ) -> Result<i64> {
        source.require_target(self, run_id)?;
        source.validate_finding(finding)?;
        let mut writer = self.storage_writer_session()?;
        self.insert_finding_at_source(
            run_id,
            finding,
            &mut writer,
            ObservationSourceWrite::Captured(source),
        )
    }
}

impl FindingSourceSnapshot {
    pub(crate) fn capture(
        &self,
        supplied: &BTreeMap<String, String>,
        findings: &[Finding],
        maximum: usize,
        canceled: &dyn Fn() -> bool,
    ) -> Result<CapturedFindingSources> {
        anyhow::ensure!(
            (1..=512 * 1024 * 1024).contains(&maximum),
            "Observation source budget must be 1 to 536870912 bytes"
        );
        let workspace = WorkspaceTarget::new(&self.root)?;
        let store = ContentStore::open(workspace.objects_dir())?;
        let files = capture_files(
            &store,
            &self.root,
            &self.tree,
            Some(supplied),
            findings,
            maximum,
            canceled,
        )?;
        Ok(CapturedFindingSources {
            root: self.root.clone(),
            snapshot: self.snapshot.clone(),
            files,
        })
    }

    pub(crate) fn capture_native(
        &self,
        findings: &[Finding],
        maximum: usize,
        canceled: &dyn Fn() -> bool,
    ) -> Result<CapturedFindingSources> {
        anyhow::ensure!(
            (1..=512 * 1024 * 1024).contains(&maximum),
            "Invalid native source capture limit"
        );
        let workspace = WorkspaceTarget::new(&self.root)?;
        let store = ContentStore::open(workspace.objects_dir())?;
        let files = capture_files(
            &store, &self.root, &self.tree, None, findings, maximum, canceled,
        )?;
        let source = CapturedFindingSources {
            root: self.root.clone(),
            snapshot: self.snapshot.clone(),
            files,
        };
        for finding in findings {
            source.validate_finding(finding)?;
        }
        Ok(source)
    }
}

fn capture_files(
    store: &ContentStore,
    root: &Path,
    tree: &ReviewSourceTree,
    supplied: Option<&BTreeMap<String, String>>,
    findings: &[Finding],
    maximum: usize,
    canceled: &dyn Fn() -> bool,
) -> Result<BTreeMap<String, CapturedFile>> {
    let mut remaining = maximum;
    let mut files = BTreeMap::new();
    for path in cited_paths(findings) {
        anyhow::ensure!(
            !canceled(),
            "Observation source capture canceled before publication"
        );
        let prefix = supplied_prefix(supplied, &path)?;
        let file = capture_file(store, root, tree, &path, prefix, remaining)?;
        remaining = remaining
            .checked_sub(file.text.len())
            .context("Source capture byte limit exceeded")?;
        files.insert(path, file);
    }
    anyhow::ensure!(
        !canceled(),
        "Observation source capture canceled before publication"
    );
    Ok(files)
}

fn supplied_prefix<'a>(
    supplied: Option<&'a BTreeMap<String, String>>,
    path: &str,
) -> Result<Option<&'a str>> {
    let Some(supplied) = supplied else {
        return Ok(None);
    };
    let prefix = supplied
        .get(path)
        .context("Cited source was not supplied to discovery")?;
    anyhow::ensure!(!prefix.is_empty(), "Supplied source prefix is empty");
    Ok(Some(prefix))
}

impl CapturedFindingSources {
    fn validate_finding(&self, finding: &Finding) -> Result<()> {
        self.evidence(&finding.evidence)?;
        anyhow::ensure!(
            self.grounding(finding)?.is_grounded(),
            "Primary anchor does not match captured source"
        );
        Ok(())
    }

    pub(crate) fn captured_counts(&self) -> (usize, usize) {
        (
            self.files.len(),
            self.files.values().map(|file| file.text.len()).sum(),
        )
    }

    fn require_target(&self, store: &FindingStore, run_id: &str) -> Result<()> {
        anyhow::ensure!(
            store
                .v3_workspace_root()
                .context("Workspace storage is missing")?
                .canonicalize()?
                == self.root.canonicalize()?,
            "Captured finding source belongs to different workspace storage"
        );
        let target: String = store.conn.query_row(
            "select target from run_states where run_id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            Path::new(&target).canonicalize()? == self.root.canonicalize()?,
            "Captured finding source belongs to a different target"
        );
        Ok(())
    }

    pub(super) fn text(&self, path: &str) -> Result<&str> {
        self.files
            .get(path)
            .map(|file| file.text.as_str())
            .context("Finding source is outside the authenticated captured files")
    }

    pub(super) fn evidence(&self, rows: &[FindingEvidence]) -> Result<Vec<FindingEvidence>> {
        for row in rows.iter().filter(|row| source_citation(row)) {
            self.require_anchor(&row.file_path, row.line)?;
            anyhow::ensure!(
                row.request_blob.is_none() && row.response_blob.is_none(),
                "Source citation contains unrelated HTTP data"
            );
            let text = self.text(&row.file_path)?;
            anyhow::ensure!(
                crate::findings::ground_against_source(text, row.line, &row.snippet, None)
                    .is_grounded(),
                "Evidence does not match authenticated captured source: {}:{}",
                row.file_path,
                row.line
            );
        }
        Ok(rows.to_vec())
    }

    pub(super) fn grounding(&self, finding: &Finding) -> Result<crate::findings::GroundingStatus> {
        self.require_primary_lines(finding)?;
        let snippet = finding
            .evidence
            .iter()
            .find(|row| {
                source_citation(row)
                    && row.file_path == finding.file_path
                    && row.line == finding.start_line
            })
            .map_or("", |row| row.snippet.as_str());
        Ok(crate::findings::ground_against_source(
            self.text(&finding.file_path)?,
            finding.start_line,
            snippet,
            self.snapshot.git_commit.clone(),
        ))
    }

    fn require_primary_lines(&self, finding: &Finding) -> Result<()> {
        self.require_anchor(&finding.file_path, finding.start_line)?;
        if let Some(end) = finding.end_line {
            self.require_anchor(&finding.file_path, end)?;
            anyhow::ensure!(
                end >= finding.start_line,
                "Primary source range is reversed"
            );
        }
        Ok(())
    }

    fn require_anchor(&self, path: &str, line: u32) -> Result<()> {
        let file = self
            .files
            .get(path)
            .context("Source anchor is outside captured membership")?;
        anyhow::ensure!(
            line > 0 && line as usize <= file.supplied_lines,
            "Source anchor is outside the supplied prefix: {path}:{line}"
        );
        Ok(())
    }

    pub(super) fn provenance(&self, finding: &Finding) -> Result<ObservationProvenance> {
        let file = self
            .files
            .get(&finding.file_path)
            .context("Primary source is not captured")?;
        let fact = FileFactWrite {
            snapshot_hash: self.snapshot.snapshot_hash.clone(),
            path: finding.file_path.clone(),
            blob_hash: file.hash.as_str().into(),
            storage_path: Some(file.storage_path.display().to_string()),
            file_size: file.text.len() as u64,
            mtime_ns: None,
            git_blob_oid: None,
            language: crate::workspace::inventory::language_for_path(Path::new(&finding.file_path))
                .map(str::to_owned),
            ast_hash: None,
            actor: "finding-store".into(),
        };
        Ok(ObservationProvenance {
            snapshot: self.snapshot.clone(),
            file: fact,
            blob_hash: file.hash.as_str().into(),
            byte_span: line_byte_span(file.text.as_bytes(), finding.start_line, finding.end_line),
        })
    }
}

fn source_citation(row: &FindingEvidence) -> bool {
    !row.is_model_generated_reasoning() && row.line > 0 && !row.file_path.is_empty()
}

fn cited_paths(findings: &[Finding]) -> BTreeSet<String> {
    findings
        .iter()
        .flat_map(|finding| {
            std::iter::once(finding.file_path.clone()).chain(
                finding
                    .evidence
                    .iter()
                    .filter(|row| source_citation(row))
                    .map(|row| row.file_path.clone()),
            )
        })
        .collect()
}

fn capture_file(
    store: &ContentStore,
    root: &Path,
    tree: &ReviewSourceTree,
    path: &str,
    prefix: Option<&str>,
    remaining: usize,
) -> Result<CapturedFile> {
    let expected = tree
        .file_hash(path)
        .context("Observation source is not in the captured tree")?;
    let full = crate::findings::safe_target_path(root, path)
        .context("Observation source path must stay inside the target")?;
    let bytes = read_capture_bytes(
        root,
        &full,
        path,
        remaining.min(MAX_OBSERVATION_SOURCE_BYTES),
    )?;
    anyhow::ensure!(
        object_hash(ObjectKind::Blob, &bytes) == expected,
        "Observation source changed before capture: {path}"
    );
    let text = String::from_utf8(bytes).context("Observation source is not UTF-8")?;
    let supplied_lines = source_line_limit(&text, prefix, path)?;
    let blob = store.put_blob(text.as_bytes())?;
    Ok(CapturedFile {
        text,
        supplied_lines,
        hash: blob.hash.clone(),
        storage_path: store.object_path(&blob.hash),
    })
}

fn source_line_limit(text: &str, prefix: Option<&str>, path: &str) -> Result<usize> {
    let Some(prefix) = prefix else {
        return Ok(text.lines().count());
    };
    anyhow::ensure!(
        text.starts_with(prefix),
        "Supplied source prefix does not match the captured tree: {path}"
    );
    Ok(prefix.lines().count())
}

fn read_capture_bytes(root: &Path, full: &Path, relative: &str, limit: usize) -> Result<Vec<u8>> {
    let file = crate::bounded_file::open_regular_file_within(root, full)
        .with_context(|| format!("Cannot retain cited source: {relative}"))?;
    let size = file.metadata()?.len();
    anyhow::ensure!(
        size <= limit as u64,
        "Capture limit {limit} B; {relative} needs {size} B"
    );
    crate::bounded_file::read_open_regular_bytes(full, file, limit)
        .with_context(|| format!("Cannot retain cited source: {relative}"))
}

#[cfg(test)]
mod tests;
