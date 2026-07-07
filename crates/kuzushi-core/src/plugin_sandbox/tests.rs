use super::*;
use crate::event_log::{EventKind, EventLog};
use crate::identity::hash_parts;
use kuzushi_sandbox::SandboxBackend;
use std::collections::BTreeMap;

fn blob_hash() -> Blake3Hash {
    hash_parts("test-blob", &[b"hello world"])
}

fn candidate(hash: Blake3Hash) -> UntrustedFindingCandidate {
    UntrustedFindingCandidate {
        rule_id: "demo.rule".to_string(),
        title: "demo finding".to_string(),
        severity: "high".to_string(),
        blob_hash: hash,
        byte_start: 0,
        byte_end: 5,
        message: "demo".to_string(),
    }
}

fn invocation_for_stdout(stdout: String, grant: GrantedSnapshot) -> PluginSandboxInvocation {
    PluginSandboxInvocation {
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "cat >/dev/null; printf '%s' '{}'",
                stdout.replace('\'', "'\\''")
            ),
        ],
        policy: SandboxPolicy {
            read_snapshot: true,
            timeout_ms: 1_000,
            ..SandboxPolicy::default()
        },
        grant,
    }
}

fn observation_context(hash: Blake3Hash) -> PluginObservationContext {
    PluginObservationContext {
        snapshot_hash: "snap3_plugin".to_string(),
        run_id: "run-plugin".to_string(),
        tool: "plugin:demo".to_string(),
        tool_version: Some("0.1.0".to_string()),
        rule_set_hash: Some("rules3_plugin".to_string()),
        actor: "plugin-sandbox".to_string(),
        display_paths: BTreeMap::from([(hash.clone(), "src/demo.rs".to_string())]),
        languages: BTreeMap::from([(hash, "rust".to_string())]),
    }
}

#[test]
fn default_policy_denies_ambient_capabilities() {
    let policy = SandboxPolicy::default();

    assert!(!policy.read_snapshot);
    assert!(!policy.write_workspace);
    assert_eq!(policy.network, NetworkPolicy::None);
    assert_eq!(policy.env, EnvPolicy::None);
}

#[test]
fn candidate_must_reference_granted_blob() {
    let grant = GrantedSnapshot::new(BTreeMap::new());

    let error = validate_candidate(candidate(blob_hash()), &grant).unwrap_err();

    assert!(error.to_string().contains("outside its granted snapshot"));
}

#[test]
fn candidate_span_must_stay_inside_blob() {
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 4)]));

    let error = validate_candidate(candidate(hash), &grant).unwrap_err();

    assert!(error.to_string().contains("byte span"));
}

#[tokio::test]
async fn sandbox_invocation_validates_stdout_candidates() {
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 11)]));
    let stdout = serde_json::json!({ "findings": [candidate(hash)] }).to_string();
    let invocation = invocation_for_stdout(stdout, grant);

    let result = run_plugin_invocation_with_backend(invocation, SandboxBackend::Plain)
        .await
        .unwrap();

    assert_eq!(
        result.backend,
        PluginSandboxBackend::Process(SandboxBackend::Plain)
    );
    assert_eq!(result.findings.len(), 1);
}

#[tokio::test]
async fn sandbox_invocation_rejects_oversized_stdout() {
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 11)]));
    let stdout = serde_json::json!({ "findings": [candidate(hash)] }).to_string();
    let mut invocation = invocation_for_stdout(stdout, grant);
    invocation.policy.max_output_bytes = 8;

    let error = run_plugin_invocation_with_backend(invocation, SandboxBackend::Plain)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("output bytes"));
}

#[test]
fn plugin_candidate_text_fields_obey_policy_cap() {
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 11)]));
    let oversized = UntrustedFindingCandidate {
        rule_id: "r1".to_string(),
        title: "too long".to_string(),
        ..candidate(hash)
    };
    let stdout = serde_json::json!({ "findings": [oversized] }).to_string();
    let policy = SandboxPolicy {
        max_field_bytes: 4,
        ..SandboxPolicy::default()
    };

    let error = validate_plugin_stdout(&stdout, &grant, &policy).unwrap_err();

    assert!(error.to_string().contains("title"));
    assert!(error.to_string().contains("exceeding policy cap"));
}

#[test]
fn plugin_stdout_rejects_unknown_top_level_fields() {
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 11)]));
    let stdout = serde_json::json!({
        "findings": [candidate(hash)],
        "eventHash": "spoofed"
    })
    .to_string();

    let error = validate_plugin_stdout(&stdout, &grant, &SandboxPolicy::default()).unwrap_err();

    assert!(error.to_string().contains("eventHash"));
}

#[test]
fn plugin_candidate_rejects_spoofed_canonical_fields() {
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 11)]));
    let mut candidate = serde_json::to_value(candidate(hash)).unwrap();
    candidate["stableFp"] = serde_json::json!("fp3_spoofed");
    candidate["triage"] = serde_json::json!({"verdict": "true_positive"});
    let stdout = serde_json::json!({ "findings": [candidate] }).to_string();

    let error = validate_plugin_stdout(&stdout, &grant, &SandboxPolicy::default()).unwrap_err();

    assert!(error.to_string().contains("stableFp"));
}

#[tokio::test]
async fn sandbox_invocation_rejects_spoofed_blob_candidate() {
    let granted = blob_hash();
    let spoofed = hash_parts("other-blob", &[b"other"]);
    let grant = GrantedSnapshot::new(BTreeMap::from([(granted, 11)]));
    let stdout = serde_json::json!({ "findings": [candidate(spoofed)] }).to_string();
    let invocation = invocation_for_stdout(stdout, grant);

    let error = run_plugin_invocation_with_backend(invocation, SandboxBackend::Plain)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("outside its granted snapshot"));
}

#[test]
fn plugin_findings_commit_through_storage_writer() {
    let tmp = tempfile::tempdir().unwrap();
    let object_path = tmp.path().join("object");
    let source = b"hello dangerous world\nsecond line\n";
    std::fs::write(&object_path, source).unwrap();
    let hash = blob_hash();
    let start = 6;
    let end = 15;
    let grant = GrantedSnapshot::with_objects([(hash.clone(), source.len() as u64, object_path)]);
    let finding = validate_candidate(
        UntrustedFindingCandidate {
            byte_start: start,
            byte_end: end,
            ..candidate(hash.clone())
        },
        &grant,
    )
    .unwrap();
    let receipts = record_plugin_findings_with_actor(
        tmp.path().join("log"),
        tmp.path().join("index.sqlite3"),
        &observation_context(hash),
        &grant,
        vec![finding],
    )
    .unwrap();

    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].committed_seq, 1);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[0].event_kind, EventKind::FindingObserved);
    assert!(events[0].payload["stableFp"]
        .as_str()
        .unwrap()
        .starts_with("fp3_"));
    assert!(events[0].payload["observationHash"]
        .as_str()
        .unwrap()
        .starts_with("obs3_"));
    assert_eq!(events[0].payload["displayLine"].as_u64(), Some(1));
}

#[test]
fn plugin_commit_requires_cas_object_bytes_for_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let hash = blob_hash();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash.clone(), 11)]));
    let finding = validate_candidate(candidate(hash.clone()), &grant).unwrap();

    let error = record_plugin_findings_with_actor(
        tmp.path().join("log"),
        tmp.path().join("index.sqlite3"),
        &observation_context(hash),
        &grant,
        vec![finding],
    )
    .unwrap_err();

    assert!(error.to_string().contains("requires a CAS object path"));
    assert!(!tmp.path().join("log").exists());
}

#[test]
fn wasm_plugin_reads_granted_blob_and_returns_validated_finding() {
    let tmp = tempfile::tempdir().unwrap();
    let object_path = tmp.path().join("object");
    let source = b"hello dangerous world\n";
    std::fs::write(&object_path, source).unwrap();
    let hash = blob_hash();
    let module_path = tmp.path().join("plugin.wasm");
    std::fs::write(&module_path, wasm_plugin_bytes(hash.as_str())).unwrap();
    let grant = GrantedSnapshot::with_objects([(hash.clone(), source.len() as u64, object_path)]);

    let result = run_wasm_plugin_invocation(WasmPluginInvocation {
        module_path,
        policy: SandboxPolicy {
            read_snapshot: true,
            max_bytes_served: 64,
            ..SandboxPolicy::default()
        },
        grant,
    })
    .unwrap();

    assert_eq!(result.backend, PluginSandboxBackend::Wasmtime);
    assert_eq!(result.findings.len(), 1);
}

#[test]
fn wasm_plugin_blob_budget_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let object_path = tmp.path().join("object");
    let source = b"hello dangerous world\n";
    std::fs::write(&object_path, source).unwrap();
    let hash = blob_hash();
    let module_path = tmp.path().join("plugin.wasm");
    std::fs::write(&module_path, wasm_plugin_bytes(hash.as_str())).unwrap();
    let grant = GrantedSnapshot::with_objects([(hash.clone(), source.len() as u64, object_path)]);

    let error = run_wasm_plugin_invocation(WasmPluginInvocation {
        module_path,
        policy: SandboxPolicy {
            read_snapshot: true,
            max_bytes_served: 4,
            ..SandboxPolicy::default()
        },
        grant,
    })
    .unwrap_err();

    assert!(error.to_string().contains("outside the granted blob"));
}

#[test]
fn wasm_plugin_cannot_read_snapshot_without_capability() {
    let tmp = tempfile::tempdir().unwrap();
    let object_path = tmp.path().join("object");
    let source = b"hello dangerous world\n";
    std::fs::write(&object_path, source).unwrap();
    let hash = blob_hash();
    let module_path = tmp.path().join("plugin.wasm");
    std::fs::write(&module_path, wasm_plugin_bytes(hash.as_str())).unwrap();
    let grant = GrantedSnapshot::with_objects([(hash.clone(), source.len() as u64, object_path)]);

    let error = run_wasm_plugin_invocation(WasmPluginInvocation {
        module_path,
        policy: SandboxPolicy {
            read_snapshot: false,
            ..SandboxPolicy::default()
        },
        grant,
    })
    .unwrap_err();

    assert!(error.to_string().contains("outside the granted blob"));
}

#[test]
fn wasm_plugin_output_budget_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let object_path = tmp.path().join("object");
    let source = b"hello dangerous world\n";
    std::fs::write(&object_path, source).unwrap();
    let hash = blob_hash();
    let module_path = tmp.path().join("plugin.wasm");
    std::fs::write(&module_path, wasm_plugin_bytes(hash.as_str())).unwrap();
    let grant = GrantedSnapshot::with_objects([(hash.clone(), source.len() as u64, object_path)]);

    let error = run_wasm_plugin_invocation(WasmPluginInvocation {
        module_path,
        policy: SandboxPolicy {
            read_snapshot: true,
            max_output_bytes: 8,
            ..SandboxPolicy::default()
        },
        grant,
    })
    .unwrap_err();

    assert!(error.to_string().contains("output exceeds policy cap"));
}

#[test]
fn wasm_plugin_timeout_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let hash = blob_hash();
    let module_path = tmp.path().join("plugin.wasm");
    std::fs::write(&module_path, infinite_wasm_plugin_bytes()).unwrap();
    let grant = GrantedSnapshot::new(BTreeMap::from([(hash, 11)]));

    let error = run_wasm_plugin_invocation(WasmPluginInvocation {
        module_path,
        policy: SandboxPolicy {
            timeout_ms: 1,
            fuel_limit: u64::MAX,
            ..SandboxPolicy::default()
        },
        grant,
    })
    .unwrap_err();

    assert!(error.to_string().contains("analyze export trapped"));
}

fn wasm_plugin_bytes(hash: &str) -> Vec<u8> {
    let output = format!(
        "{{\"findings\":[{{\"ruleId\":\"demo.rule\",\"title\":\"demo finding\",\"severity\":\"high\",\"blobHash\":\"{hash}\",\"byteStart\":6,\"byteEnd\":15,\"message\":\"demo\"}}]}}"
    );
    let denied_output = format!(
        "{{\"findings\":[{{\"ruleId\":\"demo.rule\",\"title\":\"demo finding\",\"severity\":\"high\",\"blobHash\":\"{hash}\",\"byteStart\":6,\"byteEnd\":999,\"message\":\"demo\"}}]}}"
    );
    let output_len = output.len();
    let denied_output_len = denied_output.len();
    let output = wat_string(&output);
    let denied_output = wat_string(&denied_output);
    let wat = r#"
        (module
          (import "kuzushi" "blob_read"
            (func $blob_read
              (param i32 i32 i64 i32 i32)
              (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 16) "__HASH__")
          (data (i32.const 256) "__OUTPUT__")
          (data (i32.const 1024) "__DENIED_OUTPUT__")
          (func (export "kuzushi_analyze") (result i64)
            (local $read i32)
            i32.const 16
            i32.const 64
            i64.const 6
            i32.const 128
            i32.const 9
            call $blob_read
            local.set $read
            local.get $read
            i32.const 0
            i32.lt_s
            if (result i64)
              i64.const __DENIED_OUTPUT_LEN__
              i64.const 32
              i64.shl
              i64.const 1024
              i64.or
            else
              i64.const __OUTPUT_LEN__
              i64.const 32
              i64.shl
              i64.const 256
              i64.or
            end
          )
        )
        "#;
    let wat = wat
        .replace("__HASH__", &wat_string(hash))
        .replace("__OUTPUT__", &output)
        .replace("__DENIED_OUTPUT__", &denied_output)
        .replace("__DENIED_OUTPUT_LEN__", &denied_output_len.to_string())
        .replace("__OUTPUT_LEN__", &output_len.to_string());
    wat::parse_str(wat).unwrap()
}

fn infinite_wasm_plugin_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "kuzushi_analyze") (result i64)
            loop
              br 0
            end
            i64.const 0
          )
        )
        "#,
    )
    .unwrap()
}

fn wat_string(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '"' => "\\22".to_string(),
            '\\' => "\\5c".to_string(),
            '\n' => "\\0a".to_string(),
            '\r' => "\\0d".to_string(),
            '\t' => "\\09".to_string(),
            c => c.to_string(),
        })
        .collect()
}
