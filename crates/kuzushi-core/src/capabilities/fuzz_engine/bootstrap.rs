//! Idempotent bootstrap planning over an AFE workspace.
//!
//! The engine's own artifacts are the source of truth for what already
//! happened: `workspace.json` marks init, `data/sink-scan.jsonl` marks the
//! sink scan, `targets/c/<t>/harness.cpp` marks a scaffolded target, and
//! `bin/<t>/fuzzer` marks a built one. A re-run therefore resumes instead of
//! repeating paid work (a sink re-scan is an explicit fresh-workspace choice,
//! not something this planner infers from mtimes).

use std::collections::BTreeSet;
use std::path::Path;

pub const WORKSPACE_MARKER: &str = "workspace.json";
/// The engine's own default sink-scan output name.
pub const SINKS_FILE: &str = "data/sink-scan.jsonl";

#[derive(Debug, Clone, Default)]
pub struct WorkspaceProbe {
    pub initialized: bool,
    pub sinks_present: bool,
    /// Target names under `targets/c/` that carry a harness source.
    pub targets: Vec<String>,
    /// Targets that also carry a `.localfuzz/build.json` build spec — only
    /// these can go through `target-build`; a harness without a spec is
    /// authoring work, not a build failure waiting to happen.
    pub buildable: BTreeSet<String>,
    /// Targets whose `bin/<t>/fuzzer` binary exists.
    pub built: BTreeSet<String>,
    /// Targets carrying a parked authoring workorder.
    pub workorders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapStep {
    WorkspaceInit,
    SinkScan,
    Generate,
    Build(String),
}

pub fn probe_workspace(workspace_root: &Path) -> WorkspaceProbe {
    let targets = list_targets(workspace_root);
    WorkspaceProbe {
        initialized: workspace_root.join(WORKSPACE_MARKER).is_file(),
        sinks_present: sinks_present(workspace_root),
        buildable: targets
            .iter()
            .filter(|name| build_spec_path(workspace_root, name).is_file())
            .cloned()
            .collect(),
        built: targets
            .iter()
            .filter(|name| workspace_root.join("bin").join(name).join("fuzzer").is_file())
            .cloned()
            .collect(),
        workorders: targets
            .iter()
            .filter(|name| target_workorder_path(workspace_root, name).is_file())
            .cloned()
            .collect(),
        targets,
    }
}

/// Accept the engine default plus the historic kuzushi-side name so a
/// workspace scanned under either convention never re-pays the scan.
fn sinks_present(workspace_root: &Path) -> bool {
    workspace_root.join(SINKS_FILE).is_file() || workspace_root.join("data/sinks.jsonl").is_file()
}

pub fn target_dir(workspace_root: &Path, target: &str) -> std::path::PathBuf {
    workspace_root.join("targets/c").join(target)
}

pub fn target_workorder_path(workspace_root: &Path, target: &str) -> std::path::PathBuf {
    target_dir(workspace_root, target).join(".localfuzz/workorder.json")
}

pub fn build_spec_path(workspace_root: &Path, target: &str) -> std::path::PathBuf {
    target_dir(workspace_root, target).join(".localfuzz/build.json")
}

fn list_targets(workspace_root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(workspace_root.join("targets/c")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().join("harness.cpp").is_file())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    names
}

/// Decide which bootstrap steps a run still needs. Generation only enters
/// the plan when the caller can actually drive it (a generator spec exists);
/// a workspace with harnessed targets never regenerates implicitly. Builds
/// are planned only for targets carrying a build spec.
pub fn plan_bootstrap(probe: &WorkspaceProbe, generate_available: bool) -> Vec<BootstrapStep> {
    let mut steps = Vec::new();
    if !probe.initialized {
        steps.push(BootstrapStep::WorkspaceInit);
    }
    if !probe.sinks_present {
        steps.push(BootstrapStep::SinkScan);
    }
    if probe.targets.is_empty() && generate_available {
        steps.push(BootstrapStep::Generate);
    }
    for target in &probe.targets {
        if !probe.built.contains(target) && probe.buildable.contains(target) {
            steps.push(BootstrapStep::Build(target.clone()));
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(
        initialized: bool,
        sinks: bool,
        targets: &[&str],
        buildable: &[&str],
        built: &[&str],
    ) -> WorkspaceProbe {
        WorkspaceProbe {
            initialized,
            sinks_present: sinks,
            targets: targets.iter().map(|t| t.to_string()).collect(),
            buildable: buildable.iter().map(|t| t.to_string()).collect(),
            built: built.iter().map(|t| t.to_string()).collect(),
            workorders: Vec::new(),
        }
    }

    #[test]
    fn fresh_workspace_plans_the_full_bootstrap() {
        let steps = plan_bootstrap(&probe(false, false, &[], &[], &[]), true);
        assert_eq!(
            steps,
            vec![
                BootstrapStep::WorkspaceInit,
                BootstrapStep::SinkScan,
                BootstrapStep::Generate,
            ]
        );
    }

    #[test]
    fn complete_workspace_plans_nothing() {
        let steps = plan_bootstrap(&probe(true, true, &["vhdx"], &["vhdx"], &["vhdx"]), true);
        assert!(steps.is_empty());
    }

    #[test]
    fn partial_workspace_resumes_missing_buildable_builds_only() {
        // `b` has a spec and no binary → build. `c` has a harness but no
        // build spec (the live `caching` shape) → authoring work, NOT a
        // planned build.
        let steps = plan_bootstrap(&probe(true, true, &["a", "b", "c"], &["a", "b"], &["a"]), false);
        assert_eq!(steps, vec![BootstrapStep::Build("b".to_string())]);
    }

    #[test]
    fn generation_needs_an_available_spec_and_no_existing_targets() {
        assert!(!plan_bootstrap(&probe(true, true, &[], &[], &[]), false)
            .contains(&BootstrapStep::Generate));
        assert!(!plan_bootstrap(&probe(true, true, &["t"], &["t"], &[]), true)
            .contains(&BootstrapStep::Generate));
    }

    #[test]
    fn probe_reads_engine_artifacts_from_disk() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path();
        std::fs::write(ws.join(WORKSPACE_MARKER), "{}").unwrap();
        std::fs::create_dir_all(ws.join("data")).unwrap();
        std::fs::write(ws.join(SINKS_FILE), "").unwrap();
        std::fs::create_dir_all(ws.join("targets/c/vhdx/.localfuzz")).unwrap();
        std::fs::write(ws.join("targets/c/vhdx/harness.cpp"), "// h").unwrap();
        std::fs::write(ws.join("targets/c/vhdx/.localfuzz/workorder.json"), "{}").unwrap();
        std::fs::write(ws.join("targets/c/vhdx/.localfuzz/build.json"), "{}").unwrap();
        // A harness without a build spec is a target but not buildable.
        std::fs::create_dir_all(ws.join("targets/c/caching")).unwrap();
        std::fs::write(ws.join("targets/c/caching/harness.cpp"), "// h").unwrap();
        // A dir without harness.cpp is not a target yet.
        std::fs::create_dir_all(ws.join("targets/c/empty")).unwrap();
        std::fs::create_dir_all(ws.join("bin/vhdx")).unwrap();
        std::fs::write(ws.join("bin/vhdx/fuzzer"), "").unwrap();

        let probe = probe_workspace(ws);

        assert!(probe.initialized);
        assert!(probe.sinks_present);
        assert_eq!(probe.targets, vec!["caching", "vhdx"]);
        assert!(probe.buildable.contains("vhdx"));
        assert!(!probe.buildable.contains("caching"));
        assert!(probe.built.contains("vhdx"));
        assert_eq!(probe.workorders, vec!["vhdx"]);
    }

    #[test]
    fn legacy_kuzushi_sinks_filename_also_counts_as_scanned() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("data")).unwrap();
        std::fs::write(temp.path().join("data/sinks.jsonl"), "").unwrap();
        assert!(probe_workspace(temp.path()).sinks_present);
    }
}
