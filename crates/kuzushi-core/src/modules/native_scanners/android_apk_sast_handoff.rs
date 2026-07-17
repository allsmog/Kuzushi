use super::*;

use std::path::{Path, PathBuf};

pub(in crate::modules) fn run_sast_handoff(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_step(ctx, "tool", "handoff", "android-apk:sast-handoff start");
    let layout = match resolve_handoff_layout(&target) {
        Ok(layout) => layout,
        Err(error) => {
            return Ok(failed_tool_output(
                "android-apk:sast-handoff",
                &target,
                error,
            ));
        }
    };
    emit_step(ctx, "done", "handoff", "android-apk:sast-handoff complete");
    Ok(handoff_output(&layout))
}

#[derive(Debug)]
struct HandoffLayout {
    workspace_root: PathBuf,
    decompiled_root: PathBuf,
    jadx_sources: Option<PathBuf>,
    apktool_root: Option<PathBuf>,
    raw_root: Option<PathBuf>,
    taint_sources: Option<PathBuf>,
}

fn resolve_handoff_layout(workspace_root: &Path) -> Result<HandoffLayout> {
    let requested_root = workspace_root.join("android-decompiled");
    let decompiled_root = validated_android_workspace_dir(workspace_root, &requested_root)
        .with_context(|| {
            format!(
                "android-apk:sast-handoff: missing {}. Run `android-apk:prepare` first.",
                requested_root.display()
            )
        })?;
    Ok(HandoffLayout {
        workspace_root: workspace_root.to_path_buf(),
        jadx_sources: existing_dir(&decompiled_root, &["jadx", "sources"]),
        apktool_root: existing_dir(&decompiled_root, &["apktool"]),
        raw_root: existing_dir(&decompiled_root, &["raw"]),
        taint_sources: existing_file(&decompiled_root, &["taint-sources.json"]),
        decompiled_root,
    })
}

fn existing_dir(root: &Path, parts: &[&str]) -> Option<PathBuf> {
    let path = parts.iter().fold(root.to_path_buf(), |acc, p| acc.join(p));
    std::fs::symlink_metadata(&path)
        .ok()
        .filter(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
        .map(|_| path)
}

fn existing_file(root: &Path, parts: &[&str]) -> Option<PathBuf> {
    let path = parts.iter().fold(root.to_path_buf(), |acc, p| acc.join(p));
    std::fs::symlink_metadata(&path)
        .ok()
        .filter(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
        .map(|_| path)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}

fn handoff_output(layout: &HandoffLayout) -> Value {
    let scan_target = layout
        .jadx_sources
        .as_ref()
        .unwrap_or(&layout.decompiled_root);
    let next_steps = build_next_steps(layout, scan_target);
    let summary = format!(
        "android-apk:sast-handoff: workspace ready. Hand downstream scanners {} ({} taint sources).",
        scan_target.display(),
        layout.taint_sources.is_some() as u8
    );
    json!({
        "ok": true,
        "summary": summary,
        "output": summary,
        "data": {
            "workspaceRoot": layout.workspace_root.display().to_string(),
            "decompiledRoot": layout.decompiled_root.display().to_string(),
            "jadxSources": layout.jadx_sources.as_ref().map(|p| p.display().to_string()),
            "apktoolRoot": layout.apktool_root.as_ref().map(|p| p.display().to_string()),
            "rawRoot": layout.raw_root.as_ref().map(|p| p.display().to_string()),
            "taintSourcesPath": layout.taint_sources.as_ref().map(|p| p.display().to_string()),
            "scanTarget": scan_target.display().to_string(),
            "nextSteps": next_steps,
        },
        "warnings": handoff_warnings(layout),
        "errors": [],
    })
}

fn build_next_steps(layout: &HandoffLayout, scan_target: &Path) -> Vec<String> {
    let mut steps = Vec::new();
    if layout.jadx_sources.is_some() {
        steps.push(format!(
            "kuzushi run semgrep:scan --input '{{\"target\":\"{}\"}}'",
            scan_target.display()
        ));
        steps.push(format!(
            "kuzushi run codeql:scan --input '{{\"target\":\"{}\",\"language\":\"java\"}}'",
            scan_target.display()
        ));
        steps.push(format!(
            "kuzushi run exploit-chain:scan --input '{{\"target\":\"{}\"}}'",
            scan_target.display()
        ));
        steps.push(format!(
            "kuzushi run agentic-sast:scan --input '{{\"target\":\"{}\"}}'",
            scan_target.display()
        ));
        steps.push(format!(
            "kuzushi run taint-iris-next:hunt --input '{{\"target\":\"{}\"}}'",
            scan_target.display()
        ));
        steps.push("kuzushi run android-apk:code-scan --input '{}'".to_string());
    }
    if let Some(raw) = layout.raw_root.as_ref() {
        steps.push(format!(
            "kuzushi run secret-scan:scan --input '{{\"target\":\"{}\"}}'",
            raw.display()
        ));
    }
    steps.push("kuzushi findings --severity high,critical".to_string());
    steps
}

fn handoff_warnings(layout: &HandoffLayout) -> Vec<String> {
    let mut warnings = Vec::new();
    if layout.jadx_sources.is_none() {
        warnings.push(
            "jadx output missing — Java SAST will not run. Re-run android-apk:prepare with decompiler=jadx or both."
                .to_string(),
        );
    }
    if layout.apktool_root.is_none() {
        warnings.push(
            "apktool output missing — manifest-scan / network-security-config / fileprovider-scan will fail. Re-run android-apk:prepare with decompiler=apktool or both."
                .to_string(),
        );
    }
    if layout.taint_sources.is_none() {
        warnings.push(
            "taint-sources.json missing — run android-apk:manifest-scan first so taint-iris-next can be fed Android entry points."
                .to_string(),
        );
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn populated_workspace() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let decompiled = dir.path().join("android-decompiled");
        fs::create_dir_all(decompiled.join("jadx/sources/com/example")).unwrap();
        fs::create_dir_all(decompiled.join("apktool/res/xml")).unwrap();
        fs::create_dir_all(decompiled.join("raw")).unwrap();
        fs::write(decompiled.join("taint-sources.json"), "{}").unwrap();
        dir
    }

    #[test]
    fn handoff_layout_finds_all_subtrees() {
        let dir = populated_workspace();
        let layout = resolve_handoff_layout(dir.path()).unwrap();
        assert!(layout.jadx_sources.is_some());
        assert!(layout.apktool_root.is_some());
        assert!(layout.raw_root.is_some());
        assert!(layout.taint_sources.is_some());
    }

    #[test]
    fn handoff_layout_errors_when_decompiled_missing() {
        let dir = tempdir().unwrap();
        let error = resolve_handoff_layout(dir.path()).expect_err("missing decompiled rejected");
        assert!(error.to_string().contains("Run `android-apk:prepare`"));
    }

    #[test]
    fn handoff_warnings_flag_missing_jadx() {
        let dir = tempdir().unwrap();
        let decompiled = dir.path().join("android-decompiled");
        fs::create_dir_all(decompiled.join("apktool")).unwrap();
        fs::create_dir_all(decompiled.join("raw")).unwrap();
        let layout = resolve_handoff_layout(dir.path()).unwrap();
        let warnings = handoff_warnings(&layout);
        assert!(warnings.iter().any(|w| w.contains("jadx output missing")));
    }

    #[test]
    fn build_next_steps_includes_downstream_commands_when_jadx_present() {
        let dir = populated_workspace();
        let layout = resolve_handoff_layout(dir.path()).unwrap();
        let steps = build_next_steps(&layout, layout.jadx_sources.as_ref().unwrap());
        assert!(steps.iter().any(|s| s.contains("semgrep:scan")));
        assert!(steps.iter().any(|s| s.contains("taint-iris-next:hunt")));
        assert!(steps.iter().any(|s| s.contains("secret-scan:scan")));
        assert!(steps.iter().any(|s| s.contains("android-apk:code-scan")));
    }
}
