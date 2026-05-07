//! Shared helpers for tests that need to drive the `kuzushi-eval`
//! scorer or load oracle JSONs from `experiments/xint-eval/oracles/`.
//!
//! Two consumers today: `kuzushi-cli` (`xint_recall_cli.rs`) and
//! `kuzushi-openai` (`experiment_audit_full_mode_recall_oracle.rs`).
//! Both want the same path-resolution + scorer-invocation behaviour;
//! living in a real lib keeps them in sync without copy-paste.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

/// Locate the workspace root assuming this crate sits at
/// `<root>/crates/kuzushi-eval/`.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Path to a built `kuzushi-eval` binary, building on demand if no
/// debug/release artefact is present yet.
pub fn kuzushi_eval_bin() -> PathBuf {
    let workspace = workspace_root();
    let candidates = [
        workspace.join("target/debug/kuzushi-eval"),
        workspace.join("target/release/kuzushi-eval"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    let status = Command::new("cargo")
        .args(["build", "-p", "kuzushi-eval"])
        .current_dir(&workspace)
        .status()
        .expect("cargo build of kuzushi-eval");
    assert!(status.success(), "could not build kuzushi-eval");
    workspace.join("target/debug/kuzushi-eval")
}

/// Find an oracle JSON file by `slice` field. Returns `(path, parsed)`.
pub fn load_oracle(slice: &str) -> Result<(PathBuf, Value)> {
    let oracle_dir = workspace_root()
        .join("experiments")
        .join("xint-eval")
        .join("oracles");
    let mut found: Option<PathBuf> = None;
    for entry in fs::read_dir(&oracle_dir)
        .with_context(|| format!("read oracle dir {}", oracle_dir.display()))?
    {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = fs::read_to_string(&p)?;
        let v: Value = serde_json::from_str(&body)?;
        if v["slice"].as_str() == Some(slice) {
            found = Some(p);
            break;
        }
    }
    let path = found.ok_or_else(|| anyhow!("no oracle for slice {slice}"))?;
    let body = fs::read_to_string(&path)?;
    let v: Value = serde_json::from_str(&body)?;
    Ok((path, v))
}

/// Drive the `kuzushi-eval` scorer on a `(slice, findings_dump)` pair.
/// Caller is responsible for materialising the findings dump (e.g. by
/// shelling out to `kuzushi findings --json` or by hand-rolling the
/// `{count, findings}` shape from `FindingStore::list_findings`).
pub fn run_scorer(
    slice_name: &str,
    slice_root: &Path,
    oracle_path: &Path,
    findings_dump: &Value,
) -> Result<Value> {
    let dump_path = slice_root.join("findings_dump.json");
    fs::write(&dump_path, serde_json::to_string(findings_dump)?)?;
    let scorer = kuzushi_eval_bin();
    let output = Command::new(&scorer)
        .args([
            "--oracle",
            oracle_path.to_str().unwrap(),
            "--findings",
            dump_path.to_str().unwrap(),
            "--slice",
            slice_name,
            "--target",
            slice_root.to_str().unwrap(),
            "--wall-seconds",
            "0",
        ])
        .output()
        .with_context(|| format!("invoke {}", scorer.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "kuzushi-eval failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let report: Value = serde_json::from_slice(&output.stdout)?;
    Ok(report)
}
