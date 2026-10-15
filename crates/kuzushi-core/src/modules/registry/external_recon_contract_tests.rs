mod support;
use serde_json::json;
use support::*;

#[test]
fn external_recon_actions_are_experimental_auxiliary_and_runtime_free() {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    for name in ["recon:nmap", "recon:subdomain", "recon:http-fingerprint"] {
        let tool = registry.resolve_tool(name).unwrap();
        assert_eq!(
            tool.discovery_maturity,
            Some(crate::modules::ModuleMaturity::Labs)
        );
        assert!(!tool.phase_result);
        assert_eq!(
            tool.runtime_requirement,
            crate::modules::RuntimeRequirement::Never
        );
        assert!(!registry.tool_is_discoverable(name));
        for timeout in [0, 301] {
            let mut value = input(name, "unused".into());
            value["timeoutSeconds"] = json!(timeout);
            assert!(registry.prepare_tool_input(name, value, None).is_err());
        }
    }
}

#[cfg(unix)]
#[test]
fn explicit_consent_is_required_before_an_inert_executable_runs() {
    let fixture = Fixture::new();
    let path = fixture.script(
        "owned-stub",
        &format!(
            "touch '{}'; printf 'Host: 192.0.2.10 () Ports: 80/open/tcp//http///\\n'",
            fixture.workspace.root().join("invoked").display()
        ),
    );
    assert!(fixture
        .dispatch("recon:nmap", input("recon:nmap", path), false)
        .is_err());
    assert!(!fixture.workspace.root().join("invoked").exists());
}

#[cfg(unix)]
#[test]
fn nmap_fixture_output_reaches_the_store_as_partial_external_context() {
    let fixture = Fixture::new();
    let binary = fixture.script(
        "owned-stub",
        "printf 'Host: 192.0.2.10 (owned.invalid) Ports: 80/open/tcp//http///\\n'",
    );
    let result = fixture
        .dispatch("recon:nmap", input("recon:nmap", binary), true)
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceVerified"], false);
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert_eq!(result["data"]["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["services"].as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn passive_names_are_observations_without_an_alive_claim() {
    let fixture = Fixture::new();
    let binary = fixture.script(
        "owned-stub",
        r#"printf '[{"name_value":"api.owned.invalid"}]'"#,
    );
    let mut value = input("recon:subdomain", binary);
    value["domain"] = json!("OWNED.INVALID.");
    let result = fixture.dispatch("recon:subdomain", value, true).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["hosts"][0]["state"], "unknown");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("liveness was not tested"));
    let db = rusqlite::Connection::open(fixture.workspace.findings_db_path()).unwrap();
    let metadata: String = db
        .query_row("select metadata_json from hosts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&metadata).unwrap()["livenessTested"],
        false
    );
}

#[cfg(unix)]
#[test]
fn a_single_http_fixture_retains_reported_headers_and_partial_authority() {
    let fixture = Fixture::new();
    let binary=fixture.script("owned-stub","printf 'HTTP/1.1 200 OK\\r\\nServer: OwnedFixture\\r\\n\\r\\n<html><title>Owned greeting</title></html>'");
    let result = fixture
        .dispatch(
            "recon:http-fingerprint",
            input("recon:http-fingerprint", binary),
            true,
        )
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceVerified"], false);
    assert_eq!(result["data"]["services"].as_array().unwrap().len(), 1);
}

#[test]
fn missing_dependencies_report_the_requested_binary_without_model_fallback() {
    let fixture = Fixture::new();
    for name in ["recon:nmap", "recon:subdomain", "recon:http-fingerprint"] {
        let error = fixture
            .dispatch(
                name,
                input(name, fixture.workspace.root().join("absent-program")),
                true,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("absent-program"),
            "{name}: {error:#}"
        );
    }
}

#[cfg(unix)]
#[test]
fn process_deadline_and_precancellation_leave_no_observations() {
    let fixture = Fixture::new();
    let binary = fixture.script("owned-stub", "sleep 5");
    let mut value = input("recon:nmap", binary.clone());
    value["timeoutSeconds"] = json!(1);
    let error = fixture.dispatch("recon:nmap", value, true).unwrap_err();
    assert!(format!("{error:#}").contains("process deadline reached"));
    fixture.cancel.cancel();
    assert!(fixture
        .dispatch("recon:nmap", input("recon:nmap", binary), true)
        .is_err());
    assert!(!fixture.workspace.findings_db_path().exists());
}

#[cfg(unix)]
#[test]
fn invalid_network_arguments_fail_before_the_fixture_is_invoked() {
    let fixture = Fixture::new();
    let binary = fixture.script(
        "owned-stub",
        &format!(
            "touch '{}'",
            fixture.workspace.root().join("invoked").display()
        ),
    );
    for value in [
        json!({"target":"--script=anything","ports":"80","binary":binary}),
        json!({"target":"192.0.2.10","ports":"--script=anything","binary":binary}),
        json!({"target":"192.0.2.10","ports":"65536","binary":binary}),
        json!({"target":"192.0.2.10","ports":"90-80","binary":binary}),
    ] {
        assert!(fixture.dispatch("recon:nmap", value, true).is_err());
    }
    for domain in [
        "owned.invalid&other=value",
        "owned.invalid..",
        "-owned.invalid",
        "owned..invalid",
    ] {
        assert!(fixture
            .dispatch(
                "recon:subdomain",
                json!({"domain":domain,"binary":binary}),
                true
            )
            .is_err());
    }
    assert!(!fixture.workspace.root().join("invoked").exists());
}
