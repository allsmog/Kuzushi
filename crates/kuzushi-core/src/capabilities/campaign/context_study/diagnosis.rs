use super::*;

const LEAF: &str = "rejected-context-output.txt";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedContextOutput {
    pub run_id: String,
    pub path: PathBuf,
    pub source_identity: String,
    pub model: String,
    pub text: String,
}

impl ContextStudyReceipt {
    pub fn rejected_output_available(&self, root: &Path) -> Result<bool> {
        Ok(self.diagnostic_run(root)?.is_some())
    }

    pub fn rejected_output(&self, root: &Path) -> Result<Option<RejectedContextOutput>> {
        if self.generation_tool == generation::SCOPE_TOOL {
            return self.scope_diagnostic(root);
        }
        let Some(run) = self.diagnostic_run(root)? else {
            return Ok(None);
        };
        let (path, text) =
            crate::run_artifacts::read_run_artifact_text_bounded(root, &run, LEAF, 24 * 1024 + 1)?;
        authenticate_text(root, &run, &text)?;
        Ok(Some(RejectedContextOutput {
            run_id: run,
            path,
            source_identity: self.source_identity.clone(),
            model: self.model.clone(),
            text,
        }))
    }

    pub(super) fn diagnostic_run(&self, root: &Path) -> Result<Option<String>> {
        if !self.retains_rejected_output() {
            return Ok(None);
        }
        let snapshot = super::super::snapshot::load_campaign_snapshot(root, &self.campaign_id)?;
        let job = snapshot
            .jobs
            .iter()
            .find(|job| job.job_id == JOB)
            .context("context job missing")?;
        anyhow::ensure!(
            job.tool.as_deref() == Some(self.generation_tool.as_str()),
            "context diagnostic job tool changed"
        );
        let Some(run) = &job.run_id else {
            return Ok(None);
        };
        let artifacts = crate::run_artifacts::load_run_artifacts(root, run)?;
        let leaf = if self.generation_tool == generation::SCOPE_TOOL {
            "rejected-scope-output.json"
        } else {
            LEAF
        };
        if !artifacts.iter().any(|artifact| artifact.path == leaf) {
            return Ok(None);
        }
        self.authenticate_diagnostic_input(root, run)?;
        Ok(Some(run.clone()))
    }

    fn retains_rejected_output(&self) -> bool {
        matches!(self.generation_tool.as_str(), TOOL | generation::SCOPE_TOOL)
            && self.input["saveRejectedOutput"] == true
    }

    fn authenticate_diagnostic_input(&self, root: &Path, run: &str) -> Result<()> {
        let (_, body) = crate::run_artifacts::read_run_artifact_text_bounded(
            root,
            run,
            "input.json",
            256 * 1024,
        )?;
        let input: Value = serde_json::from_str(&body)?;
        anyhow::ensure!(
            super::super::work_input_digest(&input)?
                == super::super::work_input_digest(&self.input)?,
            "rejected output input differs from the frozen context job"
        );
        Ok(())
    }
}

fn authenticate_text(root: &Path, run: &str, text: &str) -> Result<()> {
    let reference = crate::run_artifacts::load_run_artifact_object_reference(root, run, LEAF)?;
    anyhow::ensure!(
        reference.size_bytes == text.len() as u64
            && reference.hash == crate::content_store::object_hash(reference.kind, text.as_bytes()),
        "rejected context output changed since its publication"
    );
    Ok(())
}
