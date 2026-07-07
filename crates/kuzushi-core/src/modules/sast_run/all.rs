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
    pub(in crate::modules) dir: PathBuf,
    pub(in crate::modules) scan_input: PathBuf,
    pub(in crate::modules) sast_summary: PathBuf,
    pub(in crate::modules) triage_jsonl: PathBuf,
    pub(in crate::modules) verify_jsonl: PathBuf,
}

pub(in crate::modules) const SAST_SCAN_INPUT_FILE: &str = "scan-input.json";
pub(in crate::modules) const SAST_SUMMARY_FILE: &str = "sast-summary.json";
pub(in crate::modules) const SAST_TRIAGE_JSONL_FILE: &str = "triage.jsonl";
pub(in crate::modules) const SAST_VERIFY_JSONL_FILE: &str = "verify.jsonl";

impl SastRunArtifacts {
    pub(in crate::modules) fn create(workspace: &WorkspaceTarget, run_id: &str) -> Result<Self> {
        let dir = run_dir(workspace.root(), run_id);
        fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
        let triage_jsonl = dir.join(SAST_TRIAGE_JSONL_FILE);
        let verify_jsonl = dir.join(SAST_VERIFY_JSONL_FILE);
        fs::write(&triage_jsonl, "")
            .with_context(|| format!("Could not write {}", triage_jsonl.display()))?;
        fs::write(&verify_jsonl, "")
            .with_context(|| format!("Could not write {}", verify_jsonl.display()))?;
        Ok(Self {
            scan_input: dir.join(SAST_SCAN_INPUT_FILE),
            sast_summary: dir.join(SAST_SUMMARY_FILE),
            triage_jsonl,
            verify_jsonl,
            dir,
        })
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
