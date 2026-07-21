//! Tier-1 scanner-fidelity canary: deterministic, no LLM.
//!
//! Drives the planted-findings manifest in `tests/fixtures/canary-target/`
//! through the real ingest chokepoint (`workspace:import-findings` path) and
//! asserts the fidelity contracts hold: the calibration trap is CAPPED, the
//! pre-auth plant is not, and every plant lands on its closed-enum class.
//! If all three plants come back critical, trust-boundary calibration is
//! not being applied.

use kuzushi_core::findings::ingest_contract::{assign_clusters, classify};
use kuzushi_core::findings::{FindingStore, Severity};
use kuzushi_core::workspace::WorkspaceTarget;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanaryManifest {
    plants: Vec<CanaryPlant>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanaryPlant {
    id: String,
    file: String,
    line: u32,
    class: String,
    claimed_severity: String,
    precondition: String,
    expected_severity: String,
    expect_capped: bool,
    #[allow(dead_code)]
    line_window: u32,
    #[allow(dead_code)]
    why: String,
    #[allow(dead_code)]
    #[serde(default)]
    description: Option<String>,
}

fn canary_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/canary-target")
}

fn load_manifest() -> CanaryManifest {
    let path = canary_root().join("expected-findings.json");
    serde_json::from_str(&fs::read_to_string(&path).expect("canary manifest readable"))
        .expect("canary manifest parses")
}

/// Copy the canary sources into a temp workspace so imports never write
/// state into the checked-in fixture.
fn staged_canary_workspace() -> tempfile::TempDir {
    let staging = tempfile::tempdir().unwrap();
    copy_tree(&canary_root(), staging.path());
    fs::create_dir_all(staging.path().join(".kuzushi/v3")).unwrap();
    staging
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in walkdir(from) {
        let relative = entry.strip_prefix(from).unwrap();
        let destination = to.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(&entry, &destination).unwrap();
    }
}

fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn ledger_line(plant: &CanaryPlant) -> String {
    serde_json::json!({
        "file": plant.file,
        "line": plant.line,
        "title": format!("canary {}", plant.id),
        "severity": plant.claimed_severity,
        "class": plant.class,
        "precondition": plant.precondition,
        "verdict": "TRUE_POSITIVE",
    })
    .to_string()
}

#[test]
fn canary_plants_exist_where_the_manifest_says() {
    for plant in load_manifest().plants {
        let source = fs::read_to_string(canary_root().join(&plant.file))
            .unwrap_or_else(|_| panic!("canary source {} readable", plant.file));
        let marker_line = source
            .lines()
            .position(|line| line.contains(&format!("PLANT-{}", plant_suffix(&plant.id))))
            .map(|index| index as u32 + 1)
            .unwrap_or_else(|| panic!("plant marker missing in {}", plant.file));
        assert_eq!(
            marker_line, plant.line,
            "manifest line for {} drifted from the source marker",
            plant.id
        );
    }
}

fn plant_suffix(id: &str) -> String {
    id.rsplit('-').next().unwrap_or_default().to_uppercase()
}

#[test]
fn ingest_applies_severity_ceilings_exactly_as_the_manifest_expects() {
    let manifest = load_manifest();
    let staging = staged_canary_workspace();
    let ledger_path = staging.path().join("canary-ledger.jsonl");
    let body = manifest
        .plants
        .iter()
        .map(ledger_line)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&ledger_path, body).unwrap();
    let workspace = WorkspaceTarget::new(staging.path()).unwrap();

    let summary =
        kuzushi_core::findings::import::import_ledger_jsonl(&workspace, &ledger_path, "canary")
            .unwrap();
    assert_eq!(summary.imported, manifest.plants.len());

    let store = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    let findings = store.list_all_findings().unwrap();
    let mut capped_count = 0;
    for plant in &manifest.plants {
        let finding = findings
            .iter()
            .find(|finding| finding.file_path == plant.file)
            .unwrap_or_else(|| panic!("plant {} missing after import", plant.id));
        let expected = Severity::from_label(&plant.expected_severity);
        assert_eq!(
            finding.severity, expected,
            "plant {} severity drifted (calibration not applied?)",
            plant.id
        );
        if plant.expect_capped {
            capped_count += 1;
            assert_ne!(
                finding.severity,
                Severity::Critical,
                "calibration trap {} came back critical — the precondition ceiling is not being enforced",
                plant.id
            );
        }
    }
    assert!(capped_count > 0, "manifest must include a calibration trap");
}

#[test]
fn every_plant_lands_on_a_closed_enum_class_without_inference() {
    for plant in load_manifest().plants {
        let classified = classify(&plant.class, None, "");
        assert!(
            !classified.inferred,
            "plant {} class {:?} is not an exact closed-enum label",
            plant.id, plant.class
        );
    }
}

#[test]
fn nearby_plant_variants_cluster_but_distinct_files_do_not() {
    let manifest = load_manifest();
    let first = &manifest.plants[0];
    let rows = vec![
        (first.file.clone(), first.line),
        (first.file.clone(), first.line + 10),
        (manifest.plants[1].file.clone(), manifest.plants[1].line),
    ];

    let ids = assign_clusters(&rows);

    assert_eq!(ids[0], ids[1], "±15-line variants must share a cluster");
    assert_ne!(ids[0], ids[2], "plants in different files must not merge");
}
