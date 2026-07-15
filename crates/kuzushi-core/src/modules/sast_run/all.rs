use super::*;

#[derive(Debug, Clone)]
pub(in crate::modules) struct SastRunIds {
    pub(in crate::modules) primary: String,
    pub(in crate::modules) native: Option<String>,
    pub(in crate::modules) agentic: Option<String>,
    pub(in crate::modules) carlini: Option<String>,
    pub(in crate::modules) taint_iris_next: Option<String>,
    pub(in crate::modules) systems_hunt: Option<String>,
}

impl SastRunIds {
    pub(in crate::modules) fn all(&self) -> Vec<&str> {
        let ids: Vec<&str> = [
            self.native.as_deref(),
            self.agentic.as_deref(),
            self.carlini.as_deref(),
            self.taint_iris_next.as_deref(),
            self.systems_hunt.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        if ids.is_empty() {
            vec![&self.primary]
        } else {
            ids
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct SastRunArtifacts {
    workspace_root: PathBuf,
    run_id: String,
    pub(in crate::modules) dir: PathBuf,
    pub(in crate::modules) scan_input: PathBuf,
    pub(in crate::modules) sast_summary: PathBuf,
    pub(in crate::modules) triage_jsonl: PathBuf,
    pub(in crate::modules) verify_jsonl: PathBuf,
    pub(in crate::modules) patch_jsonl: PathBuf,
}

pub(in crate::modules) const SAST_SCAN_INPUT_FILE: &str = "scan-input.json";
pub(in crate::modules) const SAST_SUMMARY_FILE: &str = "sast-summary.json";
pub(in crate::modules) const SAST_TRIAGE_JSONL_FILE: &str = "triage.jsonl";
pub(in crate::modules) const SAST_VERIFY_JSONL_FILE: &str = "verify.jsonl";
pub(in crate::modules) const SAST_PATCH_JSONL_FILE: &str = "patch.jsonl";
pub(in crate::modules) use crate::run_artifacts::SAST_PHASE_STAGES_JSONL_FILE;

impl SastRunArtifacts {
    pub(in crate::modules) fn create(workspace: &WorkspaceTarget, run_id: &str) -> Result<Self> {
        let dir = crate::run_artifacts::ensure_run_dir(workspace.root(), run_id)?;
        let triage_jsonl = dir.join(SAST_TRIAGE_JSONL_FILE);
        let verify_jsonl = dir.join(SAST_VERIFY_JSONL_FILE);
        let patch_jsonl = dir.join(SAST_PATCH_JSONL_FILE);
        for leaf in [
            SAST_TRIAGE_JSONL_FILE,
            SAST_VERIFY_JSONL_FILE,
            SAST_PATCH_JSONL_FILE,
            SAST_PHASE_STAGES_JSONL_FILE,
        ] {
            let spec = crate::run_artifacts::scan_pipeline_artifact_spec(leaf)
                .context("scan pipeline artifact must be declared")?;
            crate::run_artifacts::write_run_artifact_text(
                workspace.root(),
                run_id,
                leaf,
                spec.label,
                spec.kind,
                "",
            )?;
        }
        Ok(Self {
            workspace_root: workspace.root().to_path_buf(),
            run_id: run_id.to_string(),
            scan_input: dir.join(SAST_SCAN_INPUT_FILE),
            sast_summary: dir.join(SAST_SUMMARY_FILE),
            triage_jsonl,
            verify_jsonl,
            patch_jsonl,
            dir,
        })
    }

    pub(in crate::modules) fn write_json(
        &self,
        leaf: &str,
        label: &str,
        value: &Value,
    ) -> Result<PathBuf> {
        crate::run_artifacts::write_run_artifact_json(
            &self.workspace_root,
            &self.run_id,
            leaf,
            label,
            value,
        )
        .map(|artifact| PathBuf::from(artifact.path))
    }

    pub(in crate::modules) fn append_jsonl(&self, leaf: &str, value: &Value) -> Result<()> {
        crate::run_artifacts::append_run_artifact_jsonl_value(
            &self.workspace_root,
            &self.run_id,
            leaf,
            value,
        )
        .map(|_| ())
    }

    pub(in crate::modules) fn read_text(&self, leaf: &str, label: &str) -> Result<String> {
        crate::run_artifacts::read_run_artifact_text(&self.workspace_root, &self.run_id, leaf)
            .require(label)
            .map(|(_, text)| text)
    }
}

#[cfg(test)]
mod artifact_boundary_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn jsonl_append_rejects_preplanted_symlink_leaf() {
        use std::os::unix::fs::symlink;

        let workspace_root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_root.path()).unwrap();
        let artifacts = SastRunArtifacts::create(&workspace, "scan-boundary").unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::remove_file(&artifacts.verify_jsonl).unwrap();
        std::fs::write(outside.path(), "outside sentinel\n").unwrap();
        symlink(outside.path(), &artifacts.verify_jsonl).unwrap();

        assert!(artifacts
            .append_jsonl(SAST_VERIFY_JSONL_FILE, &json!({"safe": true}))
            .is_err());
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "outside sentinel\n"
        );
    }
}

pub(in crate::modules) fn fingerprints_for_sast_runs(
    store: &FindingStore,
    run_ids: &SastRunIds,
) -> Result<Vec<String>> {
    let mut fingerprints = Vec::new();
    let mut seen = BTreeSet::new();
    for run_id in run_ids.all() {
        for finding in store.list_findings_for_scan_id(run_id)? {
            if seen.insert(finding.fingerprint.clone()) {
                fingerprints.push(finding.fingerprint);
            }
        }
    }
    Ok(fingerprints)
}
