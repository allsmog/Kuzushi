use super::*;

fn fixture() -> (Value, Value) {
    (
        json!({"status":"completed","data":{"target":"/owned/selected","kind":"dockerfile","filesScanned":1,
        "inspectedFiles":["selected/Dockerfile"],"sourceCheckCurrent":true}}),
        json!({"phase":"scan","outcome":"completed","runRefs":["owned"],"scan":{
        "scope":{"target":"/owned","paths":["selected"],"inspectedFiles":["selected/Dockerfile"]},
        "plan":{"selection":"direct","engines":["iac-scan"]},
        "engines":[{"engine":"iac-scan","outcome":"complete","runRef":"owned","ruleIds":["iac-scan/dockerfile-floating-image"]}],
        "findingDelta":{"added":1,"updated":0},"durationMs":1,"artifactDelta":[{"runRef":"owned","path":"findings.json"}],
        "targetSnapshot":{"target":"/owned","dirty":false}}}),
    )
}

fn check(output: &Value, receipt: &Value) -> Result<()> {
    validate(
        Path::new("/owned"),
        "owned",
        "iac-scan:scan",
        output,
        Some(&serde_json::from_value(receipt.clone())?),
    )
}

#[test]
fn direct_iac_scope_cannot_borrow_runs_engines_paths_members_or_policy() {
    let (output, valid) = fixture();
    check(&output, &valid).unwrap();
    for (pointer, replacement) in [
        ("/runRefs", json!(["another"])),
        ("/scan/engines/0/runRef", json!("another")),
        ("/scan/engines/0/engine", json!("license-scan")),
        ("/scan/plan/engines", json!(["cargo-audit"])),
        ("/scan/plan/selection", json!("automatic")),
        ("/scan/scope/target", json!("/elsewhere")),
        ("/scan/targetSnapshot/target", json!("/elsewhere")),
        ("/scan/scope/paths", json!(["."])),
        (
            "/scan/scope/inspectedFiles",
            json!(["selected/../Dockerfile"]),
        ),
        ("/scan/scope/inspectedFiles", json!(["selected/other"])),
        ("/scan/scope/inspectedFiles", json!(null)),
        ("/scan/engines/0/ruleIds", json!(null)),
        ("/scan/engines/0/ruleIds", json!([])),
        (
            "/scan/engines/0/ruleIds",
            json!(["iac-scan/actions-write-all-permissions"]),
        ),
        ("/scan/artifactDelta/0/runRef", json!("another")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(check(&output, &changed).is_err(), "{pointer}: {changed}");
    }
}

#[test]
fn direct_result_must_agree_on_source_outcome_membership_count_and_selected_target() {
    let (valid, receipt) = fixture();
    for (pointer, replacement) in [
        ("/status", json!("failed")),
        ("/status", json!("skipped")),
        ("/status", json!("partial")),
        ("/data/sourceCheckCurrent", json!(false)),
        ("/data/sourceCheckCurrent", json!(null)),
        ("/data/inspectedFiles", json!([])),
        ("/data/filesScanned", json!(2)),
        ("/data/target", json!("/owned/../elsewhere")),
        ("/data/kind", json!("terraform")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(check(&changed, &receipt).is_err(), "{pointer}: {changed}");
    }
}

#[test]
fn partial_receipts_keep_their_inspected_files_without_claiming_complete_coverage() {
    let (mut output, mut receipt) = fixture();
    output["status"] = json!("partial");
    output["data"]["sourceCheckCurrent"] = json!(false);
    receipt["outcome"] = json!("partial");
    receipt["scan"]["engines"][0]["outcome"] = json!("partial");
    check(&output, &receipt).unwrap();
}
