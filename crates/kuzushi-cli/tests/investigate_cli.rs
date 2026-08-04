use serde_json::Value;
use std::process::Command;

#[test]
fn prove_plan_expands_without_credentials_or_model_calls() {
    let target = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kuzushi"))
        .arg("investigate")
        .arg(target.path())
        .args(["--profile", "prove", "--plan", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["profile"], "prove");
    assert_eq!(plan["proofPolicy"], "empirical");
    assert_eq!(plan["scanInput"]["pocExecution"], true);
    assert_eq!(plan["scanInput"]["autoPatch"], Value::Null);
}

#[test]
fn fix_plan_discloses_empirical_then_patch_draft_contract() {
    let target = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kuzushi"))
        .arg("investigate")
        .arg(target.path())
        .args(["--profile", "fix", "--plan", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        plan["proofPolicy"],
        "empirical-then-build-test-checked-patch-draft"
    );
    assert_eq!(plan["targetMutation"], "none");
    assert_eq!(plan["scanInput"]["autoPatch"], true);
    assert_eq!(plan["scanInput"]["maxIterations"], 3);
}
