//! Source comparison text derives from recorded artifacts, never the checkout.
use super::*;
use kuzushi_core::run_artifacts::RunSourceRevision;

pub(super) fn source_label(app: &ShellApp, run: &str) -> String {
    source_revision(app, run).label()
}

pub(super) fn comparison_note(app: &ShellApp, left: &str, right: &str) -> &'static str {
    let left = source_revision(app, left);
    let right = source_revision(app, right);
    match left.tree_hash.zip(right.tree_hash) {
        Some((left, right)) if left.eq_ignore_ascii_case(&right) => {
            "Recorded content fingerprints match; coverage remains limited to indexed source."
        }
        Some(_) => {
            "Recorded content fingerprints differ. Check each finding against its recorded source."
        }
        None => {
            "Source content comparison unverified: at least one recorded content fingerprint is unavailable."
        }
    }
}

fn source_revision(app: &ShellApp, run: &str) -> RunSourceRevision {
    let summary = artifact_json(app, run, RUN_FILE);
    let result = artifact_json(app, run, "result.json");
    RunSourceRevision::from_artifacts(summary.as_ref(), result.as_ref())
}
