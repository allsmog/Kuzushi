use crate::modules::{ModuleMaturity, RuntimeRequirement};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn owned_record(id: &str) -> Value {
    json!({"id":id,"description":"Labeled owned metadata. No defect is claimed.",
        "cwes":[],"affected":[],"patches":[],"source":"claimed-source","raw":{}})
}

fn dispatch(input: Value) -> Value {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("ndiff:fetch-cve", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn metadata_fetch_is_experimental_auxiliary_map_work() {
    let registry = ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("ndiff:fetch-cve").unwrap();
    assert_eq!(descriptor.runtime_requirement, RuntimeRequirement::Never);
    assert_eq!(descriptor.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!descriptor.phase_result);
    assert!(!registry.tool_is_discoverable("ndiff:fetch-cve"));
}

#[test]
fn supplied_metadata_preserves_the_record_and_discloses_its_authority() {
    let record = owned_record("OWNED-ADVISORY");
    let result = dispatch(json!({"id":"owned-advisory","offline":true,"record":record}));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["record"]["id"], "OWNED-ADVISORY");
    assert_eq!(result["data"]["retrieval"]["mode"], "supplied-record");
    assert_eq!(result["data"]["retrieval"]["sourceVerified"], false);
    assert!(result["summary"]
        .as_str()
        .unwrap()
        .starts_with("Unverified supplied metadata"));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Supplied metadata; source not verified"));
}

#[test]
fn supplied_record_identity_mismatch_is_refused_without_a_fetch() {
    let result = dispatch(
        json!({"id":"OWNED-ADVISORY","offline":true,"record":owned_record("OWNED-OTHER")}),
    );
    assert_eq!(result["status"], "failed");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("does not match requested"));
}

#[test]
fn malformed_supplied_payloads_are_not_treated_as_absent() {
    for payload in [
        json!({"record":[]}),
        json!({"record":null}),
        json!({"fixtures":[]}),
    ] {
        let mut input = json!({"id":"OWNED-ADVISORY","offline":true});
        input
            .as_object_mut()
            .unwrap()
            .extend(payload.as_object().unwrap().clone());
        let result = dispatch(input);
        assert_eq!(result["status"], "failed");
        assert_eq!(result["data"]["reason"], "fetch-error");
    }
}

#[test]
fn supplied_metadata_byte_limit_is_enforced_before_parsing() {
    let result = dispatch(
        json!({"id":"OWNED-ADVISORY","offline":true,"record":owned_record("OWNED-ADVISORY"),"maxMetadataBytes":64}),
    );
    assert_eq!(result["status"], "failed");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("metadata byte limit"));
}

#[test]
fn fixture_case_lookup_preserves_identity_and_discloses_its_mode() {
    let result = dispatch(json!({"id":"owned-advisory","offline":true,
        "fixtures":{"OWNED-ADVISORY":owned_record("OWNED-ADVISORY")}}));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["retrieval"]["mode"], "supplied-fixture");
    assert_eq!(result["data"]["retrieval"]["sourceVerified"], false);
}

#[test]
#[cfg(unix)]
fn malformed_record_does_not_attempt_online_fallback() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = tempfile::tempdir().unwrap();
    let binary = fixture.path().join("owned-fetch-stub");
    std::fs::write(
        &binary,
        "#!/bin/sh\nprintf invoked > \"$0.invoked\"\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let result = dispatch(json!({"id":"OWNED-ADVISORY","offline":false,"record":[],
        "binary":binary}));
    assert_eq!(result["status"], "failed");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("metadata must be a JSON object"));
    assert!(!result["output"].as_str().unwrap().contains("requires curl"));
    assert!(!fixture.path().join("owned-fetch-stub.invoked").exists());
}

#[test]
fn metadata_limit_is_shared_by_inline_record_and_fixture_payloads() {
    let record = owned_record("OWNED-ADVISORY");
    let size = serde_json::to_vec(&record).unwrap().len();
    let result = dispatch(json!({"id":"OWNED-ADVISORY","offline":true,"record":record,
        "fixtures":{"OWNED-ADVISORY":owned_record("OWNED-ADVISORY")},"maxMetadataBytes":size+1}));
    assert_eq!(result["status"], "failed");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("metadata byte limit"));
}
