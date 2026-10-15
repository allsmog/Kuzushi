use super::WorkspaceReviewDecisionReceipt;

impl WorkspaceReviewDecisionReceipt {
    pub fn source_summary(&self) -> String {
        let Some(basis) = &self.source_basis else {
            return "source receipt unavailable".into();
        };
        format!("recorded observation {}", basis.run_id)
    }

    pub fn source_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Decision evidence: {}.", self.source_summary())];
        if let Some(basis) = &self.source_basis {
            lines.push(format!("Recorded snapshot: {}", basis.snapshot_hash));
            lines.extend(basis.source_git.as_ref().map(recorded_commit_line));
        }
        if let Some(error) = &self.source_read_error {
            lines.push(format!(
                "Decision is saved; source receipt could not be read: {error}"
            ));
        }
        lines.push("Saving a decision does not assess the current checkout. Review its source before reuse.".into());
        lines
    }
}

fn recorded_commit_line(git: &crate::RunTargetGitMetadata) -> String {
    let state = if git.dirty { "dirty" } else { "clean" };
    format!("Recorded commit: {} · {state}", git.sha)
}
