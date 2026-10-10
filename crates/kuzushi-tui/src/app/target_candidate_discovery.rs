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
    pub(crate) component_inventory: Option<kuzushi_core::SbomScanReport>,
    pub(crate) component_inventory_error: Option<String>,
    pub(crate) component_inventory_from_tool: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct StampedTargetCandidateFacts {
    pub(crate) generation: u64,
    pub(crate) facts: TargetCandidateFacts,
}

#[derive(Debug, Default)]
pub(crate) struct ActiveTargetFactsState {
    generation: u64,
    path: Option<PathBuf>,
    facts: Option<TargetCandidateFacts>,
    loading: bool,
    component_override: Option<Result<kuzushi_core::SbomScanReport, String>>,
}

impl ActiveTargetFactsState {
    pub(crate) fn begin(&mut self, path: PathBuf, generation: u64) {
        self.generation = generation;
        self.path = Some(path);
        self.facts = None;
        self.loading = true;
        self.component_override = None;
    }

    pub(crate) fn apply(&mut self, mut stamped: StampedTargetCandidateFacts) -> bool {
        if self.generation != stamped.generation || self.path.as_ref() != Some(&stamped.facts.path)
        {
            return false;
        }
        if let Some(update) = &self.component_override {
            apply_component_update(&mut stamped.facts, update);
        }
        self.facts = Some(stamped.facts);
        self.loading = false;
        true
    }

    pub(crate) fn facts(&self) -> Option<&TargetCandidateFacts> {
        self.facts.as_ref()
    }

    pub(crate) fn apply_component_inventory(
        &mut self,
        target: &std::path::Path,
        result: Result<kuzushi_core::SbomScanReport, String>,
    ) -> bool {
        if self.path.as_deref() != Some(target) {
            return false;
        }
        if let Some(facts) = self.facts.as_mut() {
            apply_component_update(facts, &result);
        }
        self.component_override = Some(result);
        true
    }

    pub(crate) fn loading(&self) -> bool {
        self.loading
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}

fn apply_component_update(
    facts: &mut TargetCandidateFacts,
    update: &Result<kuzushi_core::SbomScanReport, String>,
) {
    facts.component_inventory_from_tool = true;
    match update {
        Ok(report) => {
            facts.component_inventory = Some(report.clone());
            facts.component_inventory_error = None;
        }
        Err(error) => {
            facts.component_inventory = None;
            facts.component_inventory_error = Some(error.clone());
        }
    }
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
    facts: TargetFactsRuntime,
}

impl Default for TargetCandidateDiscoveryRuntime {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            generation: 0,
            active_cwd: None,
            tx,
            rx,
            facts: TargetFactsRuntime::default(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TargetFactsRuntime {
    generation: u64,
    active_path: Option<PathBuf>,
    tx: Sender<StampedTargetCandidateFacts>,
    rx: Receiver<StampedTargetCandidateFacts>,
}

impl Default for TargetFactsRuntime {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            generation: 0,
            active_path: None,
            tx,
            rx,
        }
    }
}

const TARGET_FACT_FILE_BUDGET: usize = 20_000;

fn inspect_target_candidate(path: PathBuf) -> TargetCandidateFacts {
    let git = kuzushi_core::workspace::target_git_metadata(&path);
    let profile = kuzushi_core::repository_inventory::TargetProfile::detect(&path);
    let inventory = kuzushi_core::repository_inventory::build_repository_inventory(&path).ok();
    let (component_inventory, component_inventory_error) =
        match kuzushi_core::scan_sbom(&path, &kuzushi_core::ScanCancellation::default()) {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        };
    let languages = detected_languages(inventory.as_ref(), &profile);
    let build_systems = detected_build_systems(&path, inventory.as_ref());
    let (file_count, file_count_capped) = bounded_file_count(&path, TARGET_FACT_FILE_BUDGET);
    let nested_scopes = detected_nested_scopes(&path);
    let (prior_artifact_count, _) =
        bounded_file_count_matching(&path.join(".kuzushi"), 5_000, is_prior_artifact_file);
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
        component_inventory,
        component_inventory_error,
        component_inventory_from_tool: false,
        path,
    }
}

fn detected_languages(
    inventory: Option<&kuzushi_core::repository_inventory::RepositoryInventory>,
    profile: &kuzushi_core::repository_inventory::TargetProfile,
) -> Vec<String> {
    let inventory_languages = inventory
        .map(|inventory| {
            inventory
                .languages
                .iter()
                .map(|language| language.name.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !inventory_languages.is_empty() {
        return inventory_languages;
    }
    profile_languages(profile)
}

fn profile_languages(profile: &kuzushi_core::repository_inventory::TargetProfile) -> Vec<String> {
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

fn detected_build_systems(
    path: &std::path::Path,
    inventory: Option<&kuzushi_core::repository_inventory::RepositoryInventory>,
) -> Vec<String> {
    let mut systems = [
        ("Cargo.toml", "Cargo"),
        ("package.json", "Node"),
        ("go.mod", "Go"),
        ("pom.xml", "Maven"),
        ("build.gradle", "Gradle"),
        ("CMakeLists.txt", "CMake"),
        ("Makefile", "Make"),
        ("BUILD", "Bazel"),
        ("BUILD.bazel", "Bazel"),
        ("WORKSPACE", "Bazel"),
        ("WORKSPACE.bazel", "Bazel"),
        ("MODULE.bazel", "Bazel"),
    ]
    .into_iter()
    .filter(|(marker, _)| path.join(marker).exists())
    .map(|(_, label)| label.to_string())
    .collect::<std::collections::BTreeSet<_>>();
    systems.extend(inventory_build_systems(inventory));
    systems.into_iter().collect()
}

fn inventory_build_systems(
    inventory: Option<&kuzushi_core::repository_inventory::RepositoryInventory>,
) -> impl Iterator<Item = String> + '_ {
    inventory
        .into_iter()
        .flat_map(|inventory| inventory.manifests.iter())
        .filter_map(|manifest| build_system_for_manifest(&manifest.kind))
        .map(str::to_string)
}

fn build_system_for_manifest(kind: &str) -> Option<&'static str> {
    const SYSTEMS: &[(&[&str], &str)] = &[
        (&["rust-cargo"], "Cargo"),
        (&["node-package"], "Node"),
        (&["python-project", "python-requirements"], "Python"),
        (&["go-module"], "Go"),
        (&["maven-project"], "Maven"),
        (&["gradle-project"], "Gradle"),
        (&["ruby-gemfile"], "Ruby"),
    ];
    SYSTEMS
        .iter()
        .find(|(kinds, _)| kinds.contains(&kind))
        .map(|(_, system)| *system)
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

/// Categories of real prior analysis. The findings index exists as soon as a
/// shell opens the target, so "findings" is claimed only when it holds one.
fn prior_artifact_categories(path: &std::path::Path) -> Vec<String> {
    let state = path.join(".kuzushi");
    let mut categories = [
        ("context", state.join("context-snapshot.json")),
        (
            "threat model",
            state.join("tm-artifacts/normalized-threat-model.json"),
        ),
        ("project model", state.join("v3/project-model")),
        ("runs", state.join("v3/runs")),
    ]
    .into_iter()
    .filter(|(_, artifact)| artifact.exists())
    .map(|(label, _)| label.to_string())
    .collect::<Vec<_>>();
    if findings_index_holds_findings(&state.join("v3/index.sqlite3")) {
        categories.push("findings".to_string());
    }
    categories
}

fn findings_index_holds_findings(index: &std::path::Path) -> bool {
    index.exists()
        && kuzushi_core::FindingStore::open_read_only(index)
            .and_then(|store| store.list_findings(1))
            .is_ok_and(|findings| !findings.is_empty())
}

/// Shell bookkeeping every session creates on open (projection indexes, their
/// SQLite sidecars, lock files, prompt history, the state `.gitignore`). None
/// of it is prior analysis, so it must not make a fresh target read as worked.
fn is_prior_artifact_file(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    let bookkeeping = matches!(name, ".gitignore" | "shell-history.txt")
        || name.starts_with("index.sqlite3")
        || name.starts_with("run-history.index.sqlite3")
        || (name.starts_with('.') && name.ends_with(".lock"));
    !bookkeeping
}

fn bounded_file_count(root: &std::path::Path, limit: usize) -> (usize, bool) {
    bounded_file_count_matching(root, limit, |_| true)
}

fn bounded_file_count_matching(
    root: &std::path::Path,
    limit: usize,
    counts: fn(&std::path::Path) -> bool,
) -> (usize, bool) {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if count_fact_entry(entry, path, &mut stack, (&mut count, limit), counts) {
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
    (count, limit): (&mut usize, usize),
    counts: fn(&std::path::Path) -> bool,
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
    if !counts(&path) {
        return false;
    }
    *count += 1;
    *count >= limit
}

fn should_descend_for_facts(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    !matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    ) && !kuzushi_core::incremental_index::is_bazel_output_component(name)
        && (!name.starts_with('.') || name == ".github")
}

impl TargetCandidateDiscoveryRuntime {
    pub(crate) fn start_facts(&mut self, path: PathBuf, wake: Option<TerminalLoopWake>) -> u64 {
        self.facts.start(path, wake)
    }

    pub(crate) fn drain_current_facts(&mut self) -> Vec<StampedTargetCandidateFacts> {
        self.facts.drain_current()
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

impl TargetFactsRuntime {
    pub(crate) fn start(&mut self, path: PathBuf, wake: Option<TerminalLoopWake>) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.active_path = Some(path.clone());
        let generation = self.generation;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let facts = inspect_target_candidate(path);
            let _ = tx.send(StampedTargetCandidateFacts { generation, facts });
            if let Some(wake) = wake {
                wake.notify();
            }
        });
        generation
    }

    pub(crate) fn drain_current(&mut self) -> Vec<StampedTargetCandidateFacts> {
        let mut current = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(stamped) if self.is_current(&stamped) => current.push(stamped),
                Ok(_) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        current
    }

    fn is_current(&self, stamped: &StampedTargetCandidateFacts) -> bool {
        stamped.generation == self.generation
            && self.active_path.as_ref() == Some(&stamped.facts.path)
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
        assert_eq!(results[0].facts.path, second.path());
        assert!(results[0]
            .facts
            .build_systems
            .contains(&"Cargo".to_string()));
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

    #[test]
    fn shell_bookkeeping_alone_is_not_prior_kuzushi_work() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("app.rs"), "fn main() {}\n").unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        drop(kuzushi_core::FindingStore::open(&workspace.findings_db_path()).unwrap());
        let v3 = target.path().join(".kuzushi/v3");
        std::fs::write(v3.join("shell-history.txt"), "setup\n").unwrap();
        std::fs::write(v3.join(".strategy-ledger.lock"), "").unwrap();

        let facts = inspect_target_candidate(target.path().to_path_buf());

        assert!(
            facts.prior_artifacts.is_empty(),
            "{:?}",
            facts.prior_artifacts
        );
        assert_eq!(facts.prior_artifact_count, 0);
    }

    #[test]
    fn generated_kuzushi_state_does_not_inflate_target_file_count() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("app.rs"), "fn main() {}\n").unwrap();
        std::fs::create_dir_all(target.path().join(".kuzushi/v3/runs/run-1")).unwrap();
        std::fs::write(
            target.path().join(".kuzushi/v3/runs/run-1/summary.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(target.path().join(".kuzushi/v3/runs/run-1/items.jsonl"), "").unwrap();

        let (target_files, target_capped) = bounded_file_count(target.path(), 100);
        let (state_files, state_capped) = bounded_file_count(&target.path().join(".kuzushi"), 100);

        assert_eq!(target_files, 1);
        assert!(!target_capped);
        assert_eq!(state_files, 2);
        assert!(!state_capped);
        assert!(prior_artifact_categories(target.path()).contains(&"runs".to_string()));
    }

    #[test]
    fn selected_facts_recognize_bazel_build_markers() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("MODULE.bazel"), "module(name='demo')").unwrap();

        let facts = inspect_target_candidate(target.path().to_path_buf());

        assert!(facts.build_systems.contains(&"Bazel".to_string()));
    }

    #[test]
    fn target_file_count_matches_analysis_directory_scope() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("src")).unwrap();
        std::fs::write(target.path().join("src/app.rs"), "fn main() {}\n").unwrap();
        std::fs::write(target.path().join(".env"), "TOKEN=fixture\n").unwrap();
        std::fs::create_dir_all(target.path().join(".github/workflows")).unwrap();
        std::fs::write(target.path().join(".github/workflows/ci.yml"), "name: ci\n").unwrap();

        for directory in [
            ".git",
            ".kuzushi",
            ".next",
            ".turbo",
            ".claude",
            "coverage",
            "dist",
            "native",
            "node_modules",
            "target",
            "bazel-out",
        ] {
            let path = target.path().join(directory);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("ignored.txt"), "generated\n").unwrap();
        }

        let (file_count, capped) = bounded_file_count(target.path(), 100);

        assert_eq!(file_count, 3);
        assert!(!capped);
        assert!(should_descend_for_facts(&target.path().join(".github")));
        assert!(!should_descend_for_facts(&target.path().join(".claude")));
        assert!(!should_descend_for_facts(&target.path().join("dist")));
        assert!(!should_descend_for_facts(&target.path().join("bazel-out")));
    }

    #[test]
    fn completed_component_result_survives_late_inspection_and_resets_on_explicit_refresh() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("package.json"),
            r#"{"dependencies":{"old-library":"^1"}}"#,
        )
        .unwrap();
        let old = inspect_target_candidate(target.path().to_path_buf());
        std::fs::write(
            target.path().join("package.json"),
            r#"{"dependencies":{"new-library":"^2"}}"#,
        )
        .unwrap();
        let report =
            kuzushi_core::scan_sbom(target.path(), &kuzushi_core::ScanCancellation::default())
                .unwrap();
        let mut state = ActiveTargetFactsState::default();
        state.begin(target.path().to_path_buf(), 2);
        assert!(state.apply_component_inventory(target.path(), Ok(report)));
        assert!(state.apply(StampedTargetCandidateFacts {
            generation: 2,
            facts: old
        }));
        let facts = state.facts().unwrap();
        assert!(facts.component_inventory_from_tool);
        assert_eq!(
            facts.component_inventory.as_ref().unwrap().components[0].name,
            "new-library"
        );
        state.begin(target.path().to_path_buf(), 3);
        let fresh = inspect_target_candidate(target.path().to_path_buf());
        assert!(state.apply(StampedTargetCandidateFacts {
            generation: 3,
            facts: fresh
        }));
        assert!(!state.facts().unwrap().component_inventory_from_tool);
    }

    #[test]
    fn component_failures_clear_stale_results_and_ignore_foreign_targets() {
        let target = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("package.json"),
            r#"{"dependencies":{"old-library":"^1"}}"#,
        )
        .unwrap();
        let old = inspect_target_candidate(target.path().to_path_buf());
        let mut state = ActiveTargetFactsState::default();
        state.begin(target.path().to_path_buf(), 2);
        assert!(!state.apply_component_inventory(foreign.path(), Err("foreign failure".into())));
        assert!(
            state.apply_component_inventory(target.path(), Err("Owned malformed manifest".into()))
        );
        assert!(state.apply(StampedTargetCandidateFacts {
            generation: 2,
            facts: old
        }));
        let facts = state.facts().unwrap();
        assert!(facts.component_inventory.is_none());
        assert_eq!(
            facts.component_inventory_error.as_deref(),
            Some("Owned malformed manifest")
        );
    }

    #[test]
    fn active_target_facts_reject_an_older_generation() {
        let target = tempfile::tempdir().unwrap();
        let facts = inspect_target_candidate(target.path().to_path_buf());
        let mut state = ActiveTargetFactsState::default();
        state.begin(target.path().to_path_buf(), 2);

        assert!(!state.apply(StampedTargetCandidateFacts {
            generation: 1,
            facts,
        }));
        assert!(state.loading());
        assert!(state.facts().is_none());
    }
}
