use super::{discover_target_candidates, TargetCandidate, TerminalLoopWake};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

#[derive(Debug)]
pub(crate) struct TargetCandidateDiscoveryResult {
    pub(crate) cwd: PathBuf,
    pub(crate) candidates: Vec<TargetCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetCandidateFacts {
    pub(crate) path: PathBuf,
    pub(crate) repository_kind: String,
    pub(crate) branch: Option<String>,
    pub(crate) revision: Option<String>,
    pub(crate) dirty: Option<bool>,
    pub(crate) languages: Vec<String>,
    pub(crate) build_systems: Vec<String>,
    pub(crate) nested_scopes: Vec<String>,
    pub(crate) file_count: usize,
    pub(crate) file_count_capped: bool,
    pub(crate) prior_artifact_count: usize,
    pub(crate) prior_artifacts: Vec<String>,
}

#[derive(Debug)]
struct StampedTargetCandidateFacts {
    generation: u64,
    facts: TargetCandidateFacts,
}

#[derive(Debug)]
struct StampedTargetCandidateDiscoveryResult {
    generation: u64,
    result: TargetCandidateDiscoveryResult,
}

#[derive(Debug)]
pub(crate) struct TargetCandidateDiscoveryRuntime {
    generation: u64,
    active_cwd: Option<PathBuf>,
    tx: Sender<StampedTargetCandidateDiscoveryResult>,
    rx: Receiver<StampedTargetCandidateDiscoveryResult>,
    facts_generation: u64,
    active_facts_path: Option<PathBuf>,
    facts_tx: Sender<StampedTargetCandidateFacts>,
    facts_rx: Receiver<StampedTargetCandidateFacts>,
}

impl Default for TargetCandidateDiscoveryRuntime {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        let (facts_tx, facts_rx) = mpsc::channel();
        Self {
            generation: 0,
            active_cwd: None,
            tx,
            rx,
            facts_generation: 0,
            active_facts_path: None,
            facts_tx,
            facts_rx,
        }
    }
}

const TARGET_FACT_FILE_BUDGET: usize = 20_000;

fn inspect_target_candidate(path: PathBuf) -> TargetCandidateFacts {
    let git = kuzushi_core::workspace::target_git_metadata(&path);
    let profile = kuzushi_core::repository_inventory::TargetProfile::detect(&path);
    let languages = detected_languages(&profile);
    let build_systems = detected_build_systems(&path);
    let (file_count, file_count_capped) = bounded_file_count(&path, TARGET_FACT_FILE_BUDGET);
    let nested_scopes = detected_nested_scopes(&path);
    let (prior_artifact_count, _) = bounded_file_count(&path.join(".kuzushi"), 5_000);
    let prior_artifacts = prior_artifact_categories(&path);
    TargetCandidateFacts {
        repository_kind: repository_kind(&git, &profile),
        branch: git.as_ref().and_then(|metadata| metadata.branch.clone()),
        revision: git.as_ref().map(|metadata| metadata.sha.clone()),
        dirty: git.as_ref().map(|metadata| metadata.dirty),
        languages,
        build_systems,
        nested_scopes,
        file_count,
        file_count_capped,
        prior_artifact_count,
        prior_artifacts,
        path,
    }
}

fn detected_languages(profile: &kuzushi_core::repository_inventory::TargetProfile) -> Vec<String> {
    let mut languages = Vec::new();
    if profile.has_rust_source {
        languages.push("Rust".to_string());
    }
    if profile.has_c_family_source {
        languages.push("C/C++".to_string());
    }
    if profile.kind == kuzushi_core::TargetKind::AndroidApk {
        languages.push("Android/JVM".to_string());
    }
    languages
}

fn detected_build_systems(path: &std::path::Path) -> Vec<String> {
    [
        ("Cargo.toml", "Cargo"),
        ("package.json", "Node"),
        ("go.mod", "Go"),
        ("pom.xml", "Maven"),
        ("build.gradle", "Gradle"),
        ("CMakeLists.txt", "CMake"),
        ("Makefile", "Make"),
    ]
    .into_iter()
    .filter(|(marker, _)| path.join(marker).exists())
    .map(|(_, label)| label.to_string())
    .collect()
}

fn detected_nested_scopes(path: &std::path::Path) -> Vec<String> {
    kuzushi_core::discover_nested_project_scopes(path)
        .non_root_scopes()
        .map(|scope| scope.rel_path.clone())
        .collect()
}

fn repository_kind(
    git: &Option<kuzushi_core::RunTargetGitMetadata>,
    profile: &kuzushi_core::repository_inventory::TargetProfile,
) -> String {
    git.as_ref()
        .map(|_| "git repository")
        .unwrap_or_else(|| profile.kind.as_str())
        .to_string()
}

fn prior_artifact_categories(path: &std::path::Path) -> Vec<String> {
    let state = path.join(".kuzushi");
    [
        ("context", state.join("context-snapshot.json")),
        (
            "threat model",
            state.join("tm-artifacts/normalized-threat-model.json"),
        ),
        ("project model", state.join("v3/project-model")),
        ("runs", state.join("v3/runs")),
        ("findings", state.join("v3/index.sqlite3")),
    ]
    .into_iter()
    .filter(|(_, artifact)| artifact.exists())
    .map(|(label, _)| label.to_string())
    .collect()
}

fn bounded_file_count(root: &std::path::Path, limit: usize) -> (usize, bool) {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if count_fact_entry(entry, path, &mut stack, &mut count, limit) {
                return (count, true);
            }
        }
    }
    (count, false)
}

fn count_fact_entry(
    entry: std::fs::DirEntry,
    path: PathBuf,
    stack: &mut Vec<PathBuf>,
    count: &mut usize,
    limit: usize,
) -> bool {
    let Ok(file_type) = entry.file_type() else {
        return false;
    };
    if file_type.is_symlink() {
        return false;
    }
    if file_type.is_dir() {
        if should_descend_for_facts(&path) {
            stack.push(path);
        }
        return false;
    }
    *count += 1;
    *count >= limit
}

fn should_descend_for_facts(path: &std::path::Path) -> bool {
    !matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "target" | "node_modules")
    )
}

impl TargetCandidateDiscoveryRuntime {
    pub(crate) fn start_facts(&mut self, path: PathBuf, wake: Option<TerminalLoopWake>) {
        self.facts_generation = self.facts_generation.wrapping_add(1);
        self.active_facts_path = Some(path.clone());
        let generation = self.facts_generation;
        let tx = self.facts_tx.clone();
        std::thread::spawn(move || {
            let facts = inspect_target_candidate(path);
            let _ = tx.send(StampedTargetCandidateFacts { generation, facts });
            if let Some(wake) = wake {
                wake.notify();
            }
        });
    }

    pub(crate) fn drain_current_facts(&mut self) -> Vec<TargetCandidateFacts> {
        let mut current = Vec::new();
        loop {
            match self.facts_rx.try_recv() {
                Ok(stamped)
                    if stamped.generation == self.facts_generation
                        && self.active_facts_path.as_ref() == Some(&stamped.facts.path) =>
                {
                    current.push(stamped.facts);
                }
                Ok(_) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        current
    }

    pub(crate) fn start(&mut self, cwd: PathBuf, wake: Option<TerminalLoopWake>) {
        self.generation = self.generation.wrapping_add(1);
        self.active_cwd = Some(cwd.clone());
        let generation = self.generation;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let candidates = discover_target_candidates(&cwd);
            let result = TargetCandidateDiscoveryResult { cwd, candidates };
            let _ = tx.send(StampedTargetCandidateDiscoveryResult { generation, result });
            if let Some(wake) = wake {
                wake.notify();
            }
        });
    }

    pub(crate) fn drain_current(&mut self) -> Vec<TargetCandidateDiscoveryResult> {
        let mut current = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(stamped) if self.is_current(&stamped) => current.push(stamped.result),
                Ok(_) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        current
    }

    fn is_current(&self, result: &StampedTargetCandidateDiscoveryResult) -> bool {
        result.generation == self.generation && self.active_cwd.as_ref() == Some(&result.result.cwd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn newer_discovery_generation_discards_older_results() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut runtime = TargetCandidateDiscoveryRuntime::default();
        runtime.start(first.path().to_path_buf(), None);
        runtime.start(second.path().to_path_buf(), None);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut results = Vec::new();
        while results.is_empty() && Instant::now() < deadline {
            results.extend(runtime.drain_current());
            std::thread::yield_now();
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cwd, second.path());
        assert_eq!(results[0].candidates[0].path, second.path());
    }

    #[test]
    fn newer_facts_generation_discards_an_older_selection() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(second.path().join("Cargo.toml"), "[package]").unwrap();
        let mut runtime = TargetCandidateDiscoveryRuntime::default();
        runtime.start_facts(first.path().to_path_buf(), None);
        runtime.start_facts(second.path().to_path_buf(), None);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut results = Vec::new();
        while results.is_empty() && Instant::now() < deadline {
            results.extend(runtime.drain_current_facts());
            std::thread::yield_now();
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, second.path());
        assert!(results[0].build_systems.contains(&"Cargo".to_string()));
    }

    #[test]
    fn selected_facts_include_nested_scope_and_prior_artifact_details() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("crates/demo/src")).unwrap();
        std::fs::write(
            target.path().join("Cargo.toml"),
            "[workspace]\nmembers=['crates/demo']\n",
        )
        .unwrap();
        std::fs::write(
            target.path().join("crates/demo/Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::create_dir_all(target.path().join(".kuzushi/v3/runs/run-1")).unwrap();
        std::fs::write(
            target.path().join(".kuzushi/v3/runs/run-1/summary.json"),
            "{}",
        )
        .unwrap();

        let facts = inspect_target_candidate(target.path().to_path_buf());

        assert!(facts
            .nested_scopes
            .iter()
            .any(|scope| scope == "crates/demo"));
        assert!(facts.prior_artifact_count > 0);
        assert!(facts.prior_artifacts.contains(&"runs".to_string()));
    }
}
