use super::prelude::*;
use super::*;

#[derive(Debug, Clone)]
pub(in crate::modules) struct SastRunIds {
    pub(in crate::modules) primary: String,
    pub(in crate::modules) native: Option<String>,
    pub(in crate::modules) agentic: Option<String>,
    pub(in crate::modules) carlini: Option<String>,
    pub(in crate::modules) taint_iris: Option<String>,
    pub(in crate::modules) taint_iris_next: Option<String>,
    pub(in crate::modules) systems_hunt: Option<String>,
}

impl SastRunIds {
    pub(in crate::modules) fn all(&self) -> Vec<&str> {
        let mut ids = Vec::new();
        if let Some(native) = self.native.as_deref() {
            ids.push(native);
        }
        if let Some(agentic) = self.agentic.as_deref() {
            ids.push(agentic);
        }
        if let Some(carlini) = self.carlini.as_deref() {
            ids.push(carlini);
        }
        if let Some(taint_iris) = self.taint_iris.as_deref() {
            ids.push(taint_iris);
        }
        if let Some(taint_iris_next) = self.taint_iris_next.as_deref() {
            ids.push(taint_iris_next);
        }
        if let Some(systems_hunt) = self.systems_hunt.as_deref() {
            ids.push(systems_hunt);
        }
        if ids.is_empty() {
            ids.push(&self.primary);
        }
        ids
    }
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct SastRunArtifacts {
    pub(in crate::modules) dir: PathBuf,
    pub(in crate::modules) summary: PathBuf,
    pub(in crate::modules) triage_jsonl: PathBuf,
    pub(in crate::modules) verify_jsonl: PathBuf,
}

impl SastRunArtifacts {
    pub(in crate::modules) fn create(workspace: &WorkspaceTarget, run_id: &str) -> Result<Self> {
        let dir = workspace.root().join(".kuzushi").join("runs").join(run_id);
        fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
        let triage_jsonl = dir.join("triage.jsonl");
        let verify_jsonl = dir.join("verify.jsonl");
        fs::write(&triage_jsonl, "")
            .with_context(|| format!("Could not write {}", triage_jsonl.display()))?;
        fs::write(&verify_jsonl, "")
            .with_context(|| format!("Could not write {}", verify_jsonl.display()))?;
        Ok(Self {
            summary: dir.join("summary.json"),
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
