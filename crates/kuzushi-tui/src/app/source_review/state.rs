use crate::app::FieldEditor;
use kuzushi_core::ScanCancellation;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceReviewMode {
    Intro,
    Capturing,
    Reading,
    Verdict,
    Reason,
    Confirm,
    Saving,
    Saved,
}

#[derive(Debug, Clone)]
pub(crate) struct SourceReviewForm {
    pub target: PathBuf,
    pub finding_id: i64,
    pub title: String,
    pub file: String,
    pub line: u32,
    pub mode: SourceReviewMode,
    pub capture: Option<serde_json::Value>,
    pub verdict: usize,
    pub reason: FieldEditor,
    pub scroll: usize,
    pub reading_scroll: usize,
    pub show_source_receipt: bool,
    pub notice: Option<String>,
    pub decision_id: Option<i64>,
}

pub(crate) const SOURCE_VERDICTS: [(&str, &str); 5] = [
    ("needs_review", "Needs review"),
    ("confirmed", "Confirmed"),
    ("rejected_false_positive", "False positive"),
    ("accepted_risk", "Accepted risk"),
    ("deferred", "Deferred"),
];

pub(crate) struct SourceReviewWorker {
    pub key: (PathBuf, i64),
    pub saving: bool,
    pub cancel: ScanCancellation,
    pub handle: Option<std::thread::JoinHandle<Result<serde_json::Value, String>>>,
}

impl std::fmt::Debug for SourceReviewWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceReviewWorker")
            .field("key", &self.key)
            .field("saving", &self.saving)
            .finish()
    }
}

impl Drop for SourceReviewWorker {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
