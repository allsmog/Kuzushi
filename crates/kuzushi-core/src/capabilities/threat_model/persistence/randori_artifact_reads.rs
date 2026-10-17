use super::super::*;
use crate::scan::ScanCancellation;
use serde::Serialize;

const MAX_NORMALIZED_BYTES: usize = 8 * 1024 * 1024;
const MAX_STAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const PLANNED_FILES: usize = 7;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactFileRead {
    pub file: String,
    pub present: Option<bool>,
    pub status: &'static str,
    pub bytes_reserved: usize,
    pub decoded_bytes: Option<usize>,
    pub sha256: Option<String>,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RandoriArtifactReadReceipt {
    pub schema_version: u32,
    pub selection_policy: &'static str,
    pub source_identity: &'static str,
    pub files_planned: usize,
    pub files_uninspected: usize,
    pub normalized_file_limit: usize,
    pub stage_file_limit: usize,
    pub total_read_reservation_limit: usize,
    pub bytes_reserved: usize,
    pub complete: bool,
    pub cancelled: bool,
    pub files: Vec<ArtifactFileRead>,
}

pub(crate) struct RandoriArtifactInspection {
    pub normalized: Option<Value>,
    pub normalized_present: bool,
    pub artifacts: RandoriArtifacts,
    pub receipt: RandoriArtifactReadReceipt,
}

impl RandoriArtifactInspection {
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.receipt
            .files
            .iter()
            .filter_map(|row| {
                row.issue
                    .as_ref()
                    .map(|issue| format!("{issue} ({})", row.file))
            })
            .collect()
    }
}

struct ArtifactReader<'a> {
    root: &'a Path,
    directory: PathBuf,
    cancellation: Option<&'a ScanCancellation>,
    files: Vec<ArtifactFileRead>,
    reserved: usize,
}

pub(crate) fn inspect_randori_artifacts(
    root: &Path,
    output_dir: &str,
    cancellation: Option<&ScanCancellation>,
) -> Result<RandoriArtifactInspection> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let directory = resolve_output_dir(workspace.root(), output_dir);
    let relative = directory
        .strip_prefix(workspace.root())
        .context("Artifact directory must stay within the selected repository")?;
    let directory = crate::workspace::validated_workspace_descendant(workspace.root(), relative)?;
    let mut reader = ArtifactReader {
        root: workspace.root(),
        directory,
        cancellation,
        files: Vec::new(),
        reserved: 0,
    };
    let normalized = reader.read("normalized-threat-model.json", MAX_NORMALIZED_BYTES);
    // An unreadable or cancelled primary is not evidence that it is absent.
    let normalized_present = reader.files[0].present != Some(false);
    let artifacts = if normalized.is_some() || !normalized_present {
        reader.read_stages()
    } else {
        RandoriArtifacts::default()
    };
    Ok(RandoriArtifactInspection {
        normalized,
        normalized_present,
        artifacts,
        receipt: reader.finish(),
    })
}

impl ArtifactReader<'_> {
    fn read_stages(&mut self) -> RandoriArtifacts {
        RandoriArtifacts {
            state: self.read("randori-state.json", MAX_STAGE_BYTES),
            s1_objectives: self.read("pasta-s1.json", MAX_STAGE_BYTES),
            s2_scope: self.read("pasta-s2.json", MAX_STAGE_BYTES),
            s3_decomposition: self.read("pasta-s3.json", MAX_STAGE_BYTES),
            s4_threats: self.read("pasta-s4.json", MAX_STAGE_BYTES),
            narrative: self.read("pasta-narrative.json", MAX_STAGE_BYTES),
        }
    }

    fn read(&mut self, file: &str, file_limit: usize) -> Option<Value> {
        if self
            .cancellation
            .is_some_and(ScanCancellation::is_cancelled)
        {
            return self.record_issue(file, None, "cancelled", "Artifact reading cancelled", 0);
        }
        let path = self.directory.join(file);
        let metadata = self.metadata(file, &path)?;
        let capacity = self.admitted_capacity(file, metadata.len(), file_limit)?;
        let reservation = capacity + 1;
        self.reserved += reservation;
        match crate::bounded_file::read_utf8_text_within(self.root, &path, capacity) {
            Ok(text) => self.parse(file, text, reservation),
            Err(error) => self.record_issue(
                file,
                Some(true),
                "unreadable",
                &format!("Artifact read failed: {error}"),
                reservation,
            ),
        }
    }

    fn admitted_capacity(&mut self, file: &str, bytes: u64, file_limit: usize) -> Option<usize> {
        if bytes > file_limit as u64 {
            self.record_issue(
                file,
                Some(true),
                "oversized",
                "Artifact exceeds its file limit",
                0,
            );
            return None;
        }
        let capacity = self.remaining_capacity(file_limit);
        if bytes > capacity as u64 || capacity == 0 {
            self.record_issue(
                file,
                Some(true),
                "omitted",
                "Artifact read allowance exhausted",
                0,
            );
            return None;
        }
        Some(capacity)
    }

    fn remaining_capacity(&self, file_limit: usize) -> usize {
        MAX_TOTAL_BYTES
            .saturating_sub(self.reserved)
            .saturating_sub(1)
            .min(file_limit)
    }

    fn metadata(&mut self, file: &str, path: &Path) -> Option<std::fs::Metadata> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => Some(metadata),
            Ok(_) => {
                self.record_issue(
                    file,
                    Some(true),
                    "unreadable",
                    "Artifact is not a regular file",
                    0,
                );
                None
            }
            Err(error) => self.metadata_error(file, error),
        }
    }

    fn metadata_error(&mut self, file: &str, error: std::io::Error) -> Option<std::fs::Metadata> {
        if error.kind() == std::io::ErrorKind::NotFound {
            self.files.push(ArtifactFileRead {
                file: file.into(),
                present: Some(false),
                status: "missing",
                bytes_reserved: 0,
                decoded_bytes: None,
                sha256: None,
                issue: None,
            });
            return None;
        }
        self.record_issue(
            file,
            None,
            "unreadable",
            &format!("Artifact metadata unavailable: {error}"),
            0,
        );
        None
    }

    fn parse(&mut self, file: &str, text: String, reservation: usize) -> Option<Value> {
        let bytes = text.len();
        self.reserved -= reservation - (bytes + 1);
        let parsed = parse_artifact(&text);
        let (status, issue) = match &parsed {
            Ok(_) => ("read", None),
            Err(error) => ("malformed", Some(error.to_string())),
        };
        self.files.push(ArtifactFileRead {
            file: file.into(),
            present: Some(true),
            status,
            bytes_reserved: bytes + 1,
            decoded_bytes: Some(bytes),
            sha256: Some(crate::run_lifecycle::sha256_content_digest(text.as_bytes())),
            issue,
        });
        parsed.ok()
    }

    fn record_issue(
        &mut self,
        file: &str,
        present: Option<bool>,
        status: &'static str,
        issue: &str,
        reserved: usize,
    ) -> Option<Value> {
        self.files.push(ArtifactFileRead {
            file: file.into(),
            present,
            status,
            bytes_reserved: reserved,
            decoded_bytes: None,
            sha256: None,
            issue: Some(issue.into()),
        });
        None
    }

    fn finish(self) -> RandoriArtifactReadReceipt {
        let cancelled = self
            .cancellation
            .is_some_and(ScanCancellation::is_cancelled);
        let complete = self.files.iter().all(|row| row.issue.is_none()) && !cancelled;
        RandoriArtifactReadReceipt {
            schema_version: 1,
            selection_policy: "seven-known-randori-artifacts",
            source_identity: "unverified",
            files_planned: PLANNED_FILES,
            files_uninspected: PLANNED_FILES - self.files.len(),
            normalized_file_limit: MAX_NORMALIZED_BYTES,
            stage_file_limit: MAX_STAGE_BYTES,
            total_read_reservation_limit: MAX_TOTAL_BYTES,
            bytes_reserved: self.reserved,
            complete,
            cancelled,
            files: self.files,
        }
    }
}

fn parse_artifact(text: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(text).context("Malformed artifact JSON")?;
    anyhow::ensure!(value.is_object(), "Artifact must contain a JSON object");
    Ok(value)
}
