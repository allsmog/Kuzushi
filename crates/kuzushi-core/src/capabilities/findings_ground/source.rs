use super::limits::GroundingLimits;
use crate::findings::{
    ground_against_source, grounding_read_error, safe_target_path, Finding, GroundingStatus,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, sync::Arc};

#[derive(Clone)]
enum CitationFile {
    Captured { source: Arc<String>, sha256: String },
    Failed(GroundingStatus),
}

pub(super) struct CitationSources<'a> {
    root: &'a Path,
    limits: GroundingLimits,
    files: BTreeMap<String, CitationFile>,
    pub(super) bytes: usize,
    pub(super) reserved_bytes: usize,
}

impl<'a> CitationSources<'a> {
    pub(super) fn new(root: &'a Path, limits: GroundingLimits) -> Self {
        Self {
            root,
            limits,
            files: BTreeMap::new(),
            bytes: 0,
            reserved_bytes: 0,
        }
    }

    pub(super) fn inspect(
        &mut self,
        finding: &Finding,
        revision: Option<&str>,
    ) -> (GroundingStatus, Value) {
        if finding.file_path.trim().is_empty()
            || finding.file_path.contains("://")
            || finding.start_line == 0
        {
            return (
                GroundingStatus::NotApplicable,
                json!({"availability":"not_applicable"}),
            );
        }
        self.capture(&finding.file_path, revision);
        let file = &self.files[&finding.file_path];
        match file {
            CitationFile::Captured { source, sha256 } => (
                ground_against_source(
                    source,
                    finding.start_line,
                    citation_snippet(finding),
                    revision.map(str::to_string),
                ),
                json!({"file":finding.file_path,"sha256":sha256,"bytes":source.len(),"availability":"captured"}),
            ),
            CitationFile::Failed(status) => (
                status.clone(),
                json!({"file":finding.file_path,"availability":status.label()}),
            ),
        }
    }

    fn capture(&mut self, path: &str, revision: Option<&str>) {
        if self.files.contains_key(path) {
            return;
        }
        let remaining = self.limits.total_bytes.saturating_sub(self.reserved_bytes);
        let file = self.read(path, revision, remaining);
        self.files.insert(path.into(), file);
    }

    fn read(&mut self, path: &str, revision: Option<&str>, remaining: usize) -> CitationFile {
        let Some(path) = safe_target_path(self.root, path) else {
            return CitationFile::Failed(GroundingStatus::Unavailable {
                reason: "Citation path must stay inside the target.".into(),
            });
        };
        if remaining == 0 {
            return CitationFile::Failed(GroundingStatus::Unavailable {
                reason: "Citation read-byte limit reached.".into(),
            });
        }
        let allowance = self.limits.per_file.min(remaining);
        self.reserved_bytes += allowance;
        match crate::bounded_file::read_regular_bytes_within(self.root, &path, allowance) {
            Ok(bytes) => self.decode(bytes, allowance),
            Err(error) => {
                CitationFile::Failed(grounding_read_error(error, revision.map(str::to_string)))
            }
        }
    }

    fn decode(&mut self, bytes: Vec<u8>, allowance: usize) -> CitationFile {
        self.reserved_bytes -= allowance - bytes.len();
        self.bytes += bytes.len();
        let sha256 = crate::run_lifecycle::sha256_content_digest(&bytes);
        match String::from_utf8(bytes) {
            Ok(source) => CitationFile::Captured {
                sha256,
                source: Arc::new(source),
            },
            Err(error) => CitationFile::Failed(GroundingStatus::Unavailable {
                reason: format!("Citation source is not UTF-8 text: {error}"),
            }),
        }
    }
}

fn citation_snippet(finding: &Finding) -> &str {
    finding
        .evidence
        .iter()
        .find(|item| {
            !item.kind.trim().eq_ignore_ascii_case("reasoning")
                && item.request_blob.is_none()
                && !item.snippet.trim().is_empty()
        })
        .map(|item| item.snippet.as_str())
        .unwrap_or("")
}
