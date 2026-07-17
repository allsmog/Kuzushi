use super::contract::COCKPIT_SPINE_CONTRACT;
use super::*;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn assert_phase_snapshot(
    contract: PhaseCompositionContract,
    width: u16,
    height: u16,
    actual: &str,
) {
    let filename = format!("phase_{}_{}x{}.snap", contract.slug, width, height);
    if let Some(root) = std::env::var_os("KUZUSHI_PHASE_SNAPSHOT_OUT") {
        write_phase_snapshot(
            &PathBuf::from(root).join(filename),
            contract,
            width,
            height,
            actual,
        );
        return;
    }
    let path = phase_snapshot_dir().join(filename);
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    assert_eq!(
        snapshot_body(&expected).trim_end(),
        actual.trim_end(),
        "{}",
        path.display()
    );
}

fn phase_snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/renderer/snapshots/phase_cockpit")
}

fn write_phase_snapshot(
    path: &Path,
    contract: PhaseCompositionContract,
    width: u16,
    height: u16,
    actual: &str,
) {
    fs::create_dir_all(path.parent().expect("phase snapshot parent"))
        .expect("phase snapshot directory");
    let document = snapshot_document(contract, width, height, actual);
    fs::write(path, document).expect("phase snapshot output");
}

fn snapshot_document(
    contract: PhaseCompositionContract,
    width: u16,
    height: u16,
    actual: &str,
) -> String {
    format!(
        "---\nsource: Kuzushi Cockpit Spine\ncontract: {COCKPIT_SPINE_CONTRACT}\nphase: {}\nsize: {width}x{height}\n---\n{}\n",
        contract.slug,
        actual.trim_end()
    )
}

fn snapshot_body(snapshot: &str) -> &str {
    snapshot
        .split_once("---\n")
        .and_then(|(_, rest)| rest.split_once("---\n"))
        .map(|(_, body)| body)
        .unwrap_or(snapshot)
}
