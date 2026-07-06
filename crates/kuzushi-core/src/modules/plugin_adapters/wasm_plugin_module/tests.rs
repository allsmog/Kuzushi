use super::*;
use crate::config::V2Config;
use crate::content_store::{object_hash, ObjectKind};
use crate::event_log::{EventKind, EventLog};
use crate::modules::ModuleRegistry;

#[test]
fn registry_runs_wasm_plugin_and_commits_v3_observation() {
    let fixture = wasm_plugin_fixture();
    let config = V2Config::default();
    let ctx = wasm_plugin_context(&config);

    let result = execute_wasm_plugin_fixture(&fixture, &ctx);

    assert_eq!(
        result.pointer("/status").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        result.pointer("/data/committedFindings").and_then(Value::as_u64),
        Some(1)
    );
    assert_finding_observed(fixture.target.path());
}

struct WasmPluginFixture {
    target: tempfile::TempDir,
    _plugin_dir: tempfile::TempDir,
    module_path: PathBuf,
}

fn wasm_plugin_fixture() -> WasmPluginFixture {
    let target = tempfile::tempdir().unwrap();
    let plugin_dir = tempfile::tempdir().unwrap();
    let source = b"hello dangerous world\n";
    std::fs::create_dir_all(target.path().join("src")).unwrap();
    std::fs::write(target.path().join("src/app.rs"), source).unwrap();
    let blob_hash = object_hash(ObjectKind::Blob, source);
    let module_path = plugin_dir.path().join("plugin.wasm");
    std::fs::write(&module_path, wasm_plugin_bytes(blob_hash.as_str())).unwrap();
    WasmPluginFixture {
        target,
        _plugin_dir: plugin_dir,
        module_path,
    }
}

fn wasm_plugin_context(config: &V2Config) -> ToolExecutionContext<'_> {
    ToolExecutionContext {
        config,
        workspace: None,
        findings_store: None,
        trace: None,
    }
}

fn execute_wasm_plugin_fixture(
    fixture: &WasmPluginFixture,
    ctx: &ToolExecutionContext<'_>,
) -> Value {
    ModuleRegistry::with_v2_builtins()
        .execute_tool(
            TOOL_NAME,
            json!({
                "target": fixture.target.path().display().to_string(),
                "modulePath": fixture.module_path.display().to_string(),
                "maxFindings": 10,
            }),
            ctx,
        )
        .unwrap()
}

fn assert_finding_observed(target: &Path) {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let events = EventLog::open(workspace.event_log_dir())
        .unwrap()
        .read_all()
        .unwrap();
    assert!(events
        .iter()
        .any(|event| event.event_kind == EventKind::FindingObserved));
}

fn wasm_plugin_bytes(hash: &str) -> Vec<u8> {
    let output = format!(
        "{{\"findings\":[{{\"ruleId\":\"demo.rule\",\"title\":\"demo finding\",\"severity\":\"high\",\"blobHash\":\"{hash}\",\"byteStart\":6,\"byteEnd\":15,\"message\":\"demo\"}}]}}"
    );
    let output_len = output.len();
    let output = wat_string(&output);
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (data (i32.const 256) "__OUTPUT__")
          (func (export "kuzushi_analyze") (result i64)
            i64.const __OUTPUT_LEN__
            i64.const 32
            i64.shl
            i64.const 256
            i64.or)
        )
        "#;
    wat::parse_str(
        wat.replace("__OUTPUT__", &output)
            .replace("__OUTPUT_LEN__", &output_len.to_string()),
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
