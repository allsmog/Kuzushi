mod support;
use serde_json::json;
use support::*;

#[test]
fn apk_pipeline_is_experimental_auxiliary_runtime_free_and_declares_limits() {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("android-apk:scan").unwrap();
    assert!(!tool.phase_result && !registry.tool_is_discoverable("android-apk:scan"));
    assert_eq!(
        tool.discovery_maturity,
        Some(crate::modules::ModuleMaturity::Labs)
    );
    assert_eq!(
        tool.runtime_requirement,
        crate::modules::RuntimeRequirement::Never
    );
    for value in [
        json!({"apk":"unused","timeoutMs":0}),
        json!({"apk":"unused","timeoutMs":86400001}),
        json!({"apk":"unused","maxApkBytes":0}),
        json!({"apk":"unused","scanContextRef":{}}),
    ] {
        assert!(registry
            .prepare_tool_input("android-apk:scan", value, None)
            .is_err());
    }
}

#[cfg(unix)]
#[test]
fn prepared_parent_consumes_owned_stage_output_and_retains_archive_identity() {
    let fixture = Fixture::new();
    let result = fixture.dispatch(fixture.input(), true).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert_eq!(result["data"]["sourceVerified"], false);
    assert_eq!(result["data"]["inputRecheck"], "matched");
    assert_eq!(
        result["data"]["inputReceipt"]["sha256"],
        crate::run_lifecycle::sha256_content_digest(&std::fs::read(&fixture.apk).unwrap())
    );
    assert!(fixture.store.list_all_findings().unwrap().len() > 0);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("manifest-scan: completed"));
}

#[cfg(unix)]
#[test]
fn skipped_scans_still_disclose_partial_coverage() {
    let fixture = Fixture::new();
    let mut value = fixture.input();
    for key in ["skipCode", "skipNative", "skipHybrid"] {
        value[key] = json!(true);
    }
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["totals"]["skipped"], 3);
    assert!(result["data"]["totals"]["findings"].as_u64().unwrap() > 0);
}

#[cfg(unix)]
#[test]
fn partial_code_inspection_keeps_findings_and_engine_error_messages() {
    let fixture = Fixture::new();
    let mut value = fixture.input();
    value["semgrepBin"]=json!(fixture.script("owned-partial-code",r#"printf '{"results":[],"errors":[{"message":"Owned partial code inspection","type":"Warning"}]}'"#));
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error
            .as_str()
            .unwrap()
            .contains("Owned partial code inspection")));
    assert!(fixture.store.list_all_findings().unwrap().len() > 0);
}

#[cfg(unix)]
#[test]
fn selected_timeout_stops_code_scanning_and_keeps_earlier_observations() {
    let fixture = Fixture::new();
    let mut value = fixture.input();
    value["semgrepBin"] = json!(fixture.script("owned-hung-code", "exec sleep 30"));
    value["timeoutMs"] = json!(5000);
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["errors"].to_string().contains("deadline"));
    assert!(fixture.store.list_all_findings().unwrap().len() > 0);
}

#[cfg(unix)]
#[test]
fn archive_changes_after_preparation_retain_original_identity_and_partial_work() {
    let fixture = Fixture::new();
    let digest = crate::run_lifecycle::sha256_content_digest(&std::fs::read(&fixture.apk).unwrap());
    let mut value = fixture.input();
    value["semgrepBin"] = json!(fixture.script(
        "owned-changing-code",
        &format!(
            "printf changed > '{}'; printf '{{\"results\":[],\"errors\":[]}}'",
            fixture.apk.display()
        )
    ));
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["inputReceipt"]["sha256"], digest);
    assert_eq!(result["data"]["inputRecheck"], "failed");
    assert!(result["errors"].to_string().contains("APK input changed"));
    assert!(fixture.store.list_all_findings().unwrap().len() > 0);
}

#[cfg(unix)]
#[test]
fn parent_timeout_and_archive_bound_stop_before_publication() {
    let fixture = Fixture::new();
    let mut value = fixture.input();
    value["unzipBin"] = json!(fixture.script("owned-hung-unzip", "exec sleep 5"));
    value["timeoutMs"] = json!(50);
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["errors"].to_string().contains("deadline"));
    let mut value = fixture.input();
    value["maxApkBytes"] = json!(1);
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["errors"].to_string().contains("inspection limit"));
    assert!(!fixture.workspace.root().join("android-decompiled").exists());
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn changing_the_archive_during_preparation_preserves_previous_output() {
    let fixture = Fixture::new();
    let old = fixture.workspace.root().join("android-decompiled");
    std::fs::create_dir(&old).unwrap();
    std::fs::write(old.join("retained.txt"), "previous output").unwrap();
    let mut value = fixture.input();
    value["apktoolBin"] = json!(fixture.script(
        "owned-changing-apktool",
        &format!("{APKTOOL}\nprintf changed > '{}'", fixture.apk.display())
    ));
    let result = fixture.dispatch(value, true).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["errors"].to_string().contains("APK input changed"));
    assert_eq!(
        std::fs::read_to_string(old.join("retained.txt")).unwrap(),
        "previous output"
    );
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn write_authorization_and_precancellation_are_required_before_stages() {
    let fixture = Fixture::new();
    assert!(fixture.dispatch(fixture.input(), false).is_err());
    fixture.cancel.cancel();
    let error = fixture.dispatch(fixture.input(), true).unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"));
    assert!(!fixture.workspace.root().join("android-decompiled").exists());
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}
