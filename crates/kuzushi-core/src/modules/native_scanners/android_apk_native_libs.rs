use super::*;

use crate::findings::Severity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(in crate::modules) fn run_native_libs_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_step(
        ctx,
        "tool",
        "scan",
        &format!("native-libs start · target={}", target.display()),
    );
    let outcome = match scan_native_libs(&input, &target) {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok(failed_tool_output(
                "android-apk:native-libs",
                &target,
                error,
            ));
        }
    };
    let persisted = persist_tool_findings(
        ctx.finding_run_id(),
        &target,
        &outcome.findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    emit_step(
        ctx,
        "done",
        "scan",
        &format!(
            "native-libs complete · {} libs, {} findings",
            outcome.libs.len(),
            outcome.findings.len()
        ),
    );
    Ok(native_libs_output(&outcome, persisted))
}

struct NativeLibsOutcome {
    lib_root: PathBuf,
    libs: Vec<NativeLibSummary>,
    findings: Vec<Finding>,
}

fn scan_native_libs(input: &Value, workspace_root: &Path) -> Result<NativeLibsOutcome> {
    let lib_root = resolve_lib_root(input, workspace_root)?;
    let lib_paths = enumerate_so_files(&lib_root)?;
    let libs = lib_paths
        .iter()
        .map(|path| {
            summarize_lib(path)
                .with_context(|| format!("could not parse native library {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let findings = native_lib_findings(&libs);
    Ok(NativeLibsOutcome {
        lib_root,
        libs,
        findings,
    })
}

fn resolve_lib_root(input: &Value, workspace_root: &Path) -> Result<PathBuf> {
    let candidate = if let Some(raw) = input
        .get("libRoot")
        .or_else(|| input.get("lib_root"))
        .and_then(Value::as_str)
    {
        PathBuf::from(raw)
    } else {
        workspace_root
            .join("android-decompiled")
            .join("raw")
            .join("lib")
    };
    validated_android_workspace_dir(workspace_root, &candidate).with_context(|| {
        format!(
            "android-apk:native-libs: missing {}. APK has no native libraries or `android-apk:prepare` hasn't run.",
            candidate.display()
        )
    })
}

fn native_lib_findings(libs: &[NativeLibSummary]) -> Vec<Finding> {
    libs.iter().flat_map(per_lib_findings).collect()
}

fn per_lib_findings(lib: &NativeLibSummary) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path = lib.path.display().to_string();
    if !lib.dangerous_imports.is_empty() {
        findings.push(dangerous_imports_finding(lib, &path));
    }
    if !lib.jni_exports.is_empty() {
        findings.push(jni_exports_finding(lib, &path));
    }
    findings
}

fn dangerous_imports_finding(lib: &NativeLibSummary, path: &str) -> Finding {
    Finding::new_tool(
        "android-apk",
        "android-apk:native-dangerous-imports",
        path,
        1,
        None,
        Severity::Medium,
        format!(
            "Native library {} (ABI {}) imports {:?}. Check whether attacker-controlled input reaches these APIs (command injection, library injection, memory-corruption primitives).",
            lib.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>"),
            lib.abi,
            lib.dangerous_imports
        ),
    )
}

fn jni_exports_finding(lib: &NativeLibSummary, path: &str) -> Finding {
    let preview = jni_exports_preview(&lib.jni_exports);
    Finding::new_tool(
        "android-apk",
        "android-apk:native-jni-exports",
        path,
        1,
        None,
        Severity::Info,
        format!(
            "Native library {} (ABI {}) exports {} JNI functions. Attack surface — example exports: {}. Cross-reference against Java callsites in jadx sources to find unguarded entry points.",
            lib.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>"),
            lib.abi,
            lib.jni_exports.len(),
            preview
        ),
    )
}

fn jni_exports_preview(exports: &[String]) -> String {
    exports
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ")
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}

fn native_libs_output(
    outcome: &NativeLibsOutcome,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    let summary = format!(
        "android-apk:native-libs: {} libraries scanned under {} ({} findings)",
        outcome.libs.len(),
        outcome.lib_root.display(),
        outcome.findings.len()
    );
    json!({
        "ok": true,
        "summary": summary,
        "output": summary,
        "data": {
            "libRoot": outcome.lib_root.display().to_string(),
            "libs": outcome.libs.iter().map(lib_summary_json).collect::<Vec<_>>(),
            "abiCount": count_per_abi(&outcome.libs),
            "findings": outcome.findings,
            "persisted": persisted,
        },
        "warnings": [],
        "errors": [],
    })
}

fn lib_summary_json(lib: &NativeLibSummary) -> Value {
    json!({
        "path": lib.path.display().to_string(),
        "abi": lib.abi,
        "sizeBytes": lib.size_bytes,
        "jniExportCount": lib.jni_exports.len(),
        "dangerousImports": lib.dangerous_imports,
    })
}

fn count_per_abi(libs: &[NativeLibSummary]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for lib in libs {
        *counts.entry(lib.abi.clone()).or_insert(0) += 1;
    }
    json!(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_lib_root_errors_when_missing() {
        let dir = tempdir().unwrap();
        let error = resolve_lib_root(&json!({}), dir.path()).expect_err("missing rejected");
        assert!(error.to_string().contains("no native libraries"));
    }

    #[test]
    fn dangerous_imports_finding_message_lists_symbols() {
        let lib = NativeLibSummary {
            path: PathBuf::from("/tmp/libfoo.so"),
            abi: "arm64-v8a".into(),
            size_bytes: 1234,
            jni_exports: Vec::new(),
            dangerous_imports: vec!["system".into(), "execve".into()],
        };
        let finding = dangerous_imports_finding(&lib, "/tmp/libfoo.so");
        assert!(finding.message.contains("system"));
        assert!(finding.message.contains("execve"));
        assert_eq!(finding.severity.as_str(), "medium");
    }

    #[test]
    fn jni_exports_preview_shortens_long_lists() {
        let exports: Vec<String> = (0..10).map(|i| format!("Java_com_example_M{i}")).collect();
        let preview = jni_exports_preview(&exports);
        assert!(preview.contains("Java_com_example_M0"));
        assert!(preview.contains("Java_com_example_M4"));
        assert!(!preview.contains("Java_com_example_M5"));
    }

    #[test]
    fn count_per_abi_groups_libraries_by_abi() {
        let libs = vec![
            NativeLibSummary {
                path: PathBuf::from("libfoo.so"),
                abi: "arm64-v8a".into(),
                size_bytes: 1,
                jni_exports: Vec::new(),
                dangerous_imports: Vec::new(),
            },
            NativeLibSummary {
                path: PathBuf::from("libbar.so"),
                abi: "arm64-v8a".into(),
                size_bytes: 1,
                jni_exports: Vec::new(),
                dangerous_imports: Vec::new(),
            },
            NativeLibSummary {
                path: PathBuf::from("libbaz.so"),
                abi: "armeabi-v7a".into(),
                size_bytes: 1,
                jni_exports: Vec::new(),
                dangerous_imports: Vec::new(),
            },
        ];
        let counts = count_per_abi(&libs);
        assert_eq!(counts.get("arm64-v8a").and_then(Value::as_u64), Some(2));
        assert_eq!(counts.get("armeabi-v7a").and_then(Value::as_u64), Some(1));
    }
}
