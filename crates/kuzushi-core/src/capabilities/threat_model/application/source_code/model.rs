use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub(crate) struct CodeEvidence {
    pub(crate) prompt: String,
    pub(crate) references: BTreeSet<String>,
}

impl CodeEvidence {
    pub(crate) fn append_to(&self, prompt: String) -> String {
        if self.prompt.is_empty() {
            return prompt;
        }
        format!("{prompt}\n\n{}", self.prompt)
    }
}

pub(crate) struct CodeSource {
    pub(crate) content: String,
    pub(crate) partial: bool,
    pub(crate) references: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(super) struct Candidate {
    pub(super) path: String,
    pub(super) citation_path: String,
    pub(super) language: String,
    pub(super) anchors: Vec<usize>,
}

pub(super) struct Selection {
    pub(super) scope_path: String,
    pub(super) eligible: usize,
    pub(super) files: Vec<Candidate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CodeReport {
    pub(super) policy: &'static str,
    pub(super) scope_path: String,
    pub(super) tree_hash: String,
    pub(super) byte_budget: usize,
    pub(super) file_limit: usize,
    pub(super) eligible_files: usize,
    pub(super) selected_files: usize,
    pub(super) read_bytes: usize,
    pub(super) omissions: BTreeMap<&'static str, usize>,
    pub(super) files: Vec<FileExcerpt>,
}

impl CodeReport {
    pub(super) fn partial(&self) -> bool {
        self.files.len() < self.eligible_files
            || self.files.iter().any(|file| file.omitted_lines > 0)
    }

    pub(super) fn omit(&mut self, reason: &'static str) {
        *self.omissions.entry(reason).or_default() += 1;
    }

    pub(super) fn references(&self) -> BTreeSet<String> {
        self.files
            .iter()
            .flat_map(|file| file.lines.iter().map(|line| line.reference.clone()))
            .collect()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FileExcerpt {
    pub(super) path: String,
    pub(super) language: String,
    pub(super) file_sha256: String,
    pub(super) projection: &'static str,
    pub(super) total_lines: usize,
    pub(super) excluded_test_lines: usize,
    pub(super) omitted_lines: usize,
    pub(super) lines: Vec<CodeLine>,
}

#[derive(Debug, Serialize)]
pub(super) struct CodeLine {
    #[serde(rename = "ref")]
    pub(super) reference: String,
    pub(super) text: String,
}
