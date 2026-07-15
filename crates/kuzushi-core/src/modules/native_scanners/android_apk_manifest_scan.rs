use super::*;

use crate::findings::Severity;
use std::path::{Path, PathBuf};

pub(in crate::modules) struct ManifestScanInputs {
    pub(in crate::modules) manifest_path: PathBuf,
    pub(in crate::modules) taint_sources_path: PathBuf,
}

pub(in crate::modules) fn resolve_manifest_inputs(
    input: &Value,
    workspace_root: &Path,
) -> Result<ManifestScanInputs> {
    let decompiled_root = decompiled_root_from(input, workspace_root)?;
    let requested_manifest = decompiled_root.join("apktool").join("AndroidManifest.xml");
    let manifest_path = validated_android_workspace_file(workspace_root, &requested_manifest)
        .with_context(|| {
            format!(
                "android-apk:manifest-scan: missing {}. Run `android-apk:prepare` first.",
                requested_manifest.display()
            )
        })?;
    let taint_sources_path = decompiled_root.join("taint-sources.json");
    Ok(ManifestScanInputs {
        manifest_path,
        taint_sources_path,
    })
}

fn decompiled_root_from(input: &Value, workspace_root: &Path) -> Result<PathBuf> {
    let candidate = if let Some(raw) = input
        .get("decompiledRoot")
        .or_else(|| input.get("decompiled_root"))
        .and_then(Value::as_str)
    {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            workspace_root.join("android-decompiled")
        }
    } else {
        workspace_root.join("android-decompiled")
    };
    validated_android_workspace_dir(workspace_root, &candidate)
}

pub(in crate::modules) fn run_manifest_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_manifest_scan_step(ctx, "tool", "manifest-scan start", &target, None);
    let scan = match collect_manifest_scan(&input, &target) {
        Ok(scan) => scan,
        Err(error) => return Ok(manifest_scan_failed_output(&target, error)),
    };
    let persisted = persist_tool_findings(
        ctx.finding_run_id(),
        &target,
        &scan.findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    emit_manifest_scan_step(
        ctx,
        "done",
        "manifest-scan complete",
        &target,
        Some(scan.findings.len()),
    );
    Ok(manifest_scan_output(
        &scan.inputs,
        &scan.manifest,
        scan.findings,
        persisted,
        scan.taint_summary,
    ))
}

struct ManifestScan {
    inputs: ManifestScanInputs,
    manifest: ParsedManifest,
    findings: Vec<Finding>,
    taint_summary: TaintSourcesSummary,
}

fn collect_manifest_scan(input: &Value, target: &Path) -> Result<ManifestScan> {
    let inputs = resolve_manifest_inputs(input, target)?;
    let manifest = parse_manifest_file(&inputs.manifest_path)?;
    let findings = collect_manifest_findings(&manifest, &inputs.manifest_path);
    let taint_summary = write_taint_sources(&manifest, target, &inputs.taint_sources_path)?;
    Ok(ManifestScan {
        inputs,
        manifest,
        findings,
        taint_summary,
    })
}

fn manifest_scan_failed_output(target: &Path, error: anyhow::Error) -> Value {
    failed_tool_output("android-apk:manifest-scan", target, error)
}

fn emit_manifest_scan_step(
    ctx: &ToolExecutionContext<'_>,
    kind: &str,
    label: &str,
    target: &Path,
    findings_count: Option<usize>,
) {
    let Some(trace) = ctx.trace else {
        return;
    };
    let suffix = findings_count
        .map(|count| format!(" · {count} findings"))
        .unwrap_or_else(|| format!(" · target={}", target.display()));
    let _ = trace.step(kind, "scan", format!("{label}{suffix}")).emit();
}

fn collect_manifest_findings(manifest: &ParsedManifest, manifest_path: &Path) -> Vec<Finding> {
    let path = manifest_path.display().to_string();
    let mut findings = Vec::new();
    findings.extend(check_application_flags(manifest, &path));
    findings.extend(check_components(manifest, &path));
    findings.extend(check_deeplinks(manifest, &path));
    findings
}

fn check_application_flags(manifest: &ParsedManifest, manifest_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let app = &manifest.application;
    if app.debuggable == Some(true) {
        findings.push(finding_at("android-apk:debuggable-true", manifest_path, 1, Severity::High,
            "Application declares android:debuggable=\"true\" (CWE-489). Anyone with adb access can attach JDWP and read memory; ship with debuggable disabled."));
    }
    if app.allow_backup == Some(true) {
        findings.push(finding_at("android-apk:allow-backup-true", manifest_path, 2, Severity::Medium,
            "Application declares android:allowBackup=\"true\" (CWE-921). adb backup can extract app data when USB debugging is enabled."));
    }
    if app.uses_cleartext_traffic == Some(true) {
        findings.push(finding_at("android-apk:cleartext-traffic", manifest_path, 3, Severity::Medium,
            "Application declares android:usesCleartextTraffic=\"true\" (CWE-319). HTTP traffic is permitted; prefer scoped network-security-config."));
    }
    findings
}

fn check_components(manifest: &ParsedManifest, manifest_path: &str) -> Vec<Finding> {
    manifest
        .components
        .iter()
        .enumerate()
        .flat_map(|(index, component)| component_findings(component, manifest_path, index))
        .collect()
}

fn component_findings(component: &Component, manifest_path: &str, index: usize) -> Vec<Finding> {
    if !component.is_effectively_exported() {
        return Vec::new();
    }
    let line = component_synthetic_line(index);
    let mut findings = Vec::new();
    if component.permission.is_none() {
        findings.push(exported_no_permission_finding(
            component,
            manifest_path,
            line,
        ));
    }
    findings.extend(provider_findings(component, manifest_path, line));
    findings
}

fn component_synthetic_line(index: usize) -> u32 {
    // Each manifest component finding shares the same file path and CWE; the
    // findings-store dedup key buckets line numbers in groups of 16, so we
    // space synthetic lines by 16 here to keep one entry per component.
    1 + (index as u32) * 16
}

fn provider_findings(component: &Component, manifest_path: &str, line: u32) -> Vec<Finding> {
    if !matches!(component.kind, ComponentKind::Provider) {
        return Vec::new();
    }
    check_provider_export(component, manifest_path, line)
        .into_iter()
        .collect()
}

fn exported_no_permission_finding(
    component: &Component,
    manifest_path: &str,
    line: u32,
) -> Finding {
    let label = component.kind.label();
    finding_at(
        &format!("android-apk:exported-{label}-no-permission"),
        manifest_path,
        line,
        Severity::High,
        &format!(
            "{label} {:?} is exported without android:permission (CWE-926). Any other app can invoke it via Intent.",
            component.name
        ),
    )
}

fn check_provider_export(component: &Component, manifest_path: &str, line: u32) -> Option<Finding> {
    if component.grant_uri_permissions == Some(true) {
        return None;
    }
    Some(finding_at(
        "android-apk:provider-exported-no-grant",
        manifest_path,
        line,
        Severity::High,
        &format!(
            "ContentProvider {:?} is exported without android:grantUriPermissions (CWE-200). Path traversal and arbitrary file read are likely.",
            component.name
        ),
    ))
}

fn check_deeplinks(manifest: &ParsedManifest, manifest_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, component) in manifest.components.iter().enumerate() {
        for (filter_index, filter) in component.intent_filters.iter().enumerate() {
            if !filter.is_browseable_deeplink() {
                continue;
            }
            let line = component_synthetic_line(index) + (filter_index as u32);
            findings.push(finding_at(
                "android-apk:browseable-deeplink",
                manifest_path,
                line,
                Severity::Info,
                &format!(
                    "Browseable deeplink on {} {:?}: schemes={:?} hosts={:?}. Trace deeplink handling for taint into sensitive sinks.",
                    component.kind.label(),
                    component.name,
                    filter.schemes,
                    filter.hosts
                ),
            ));
        }
    }
    findings
}

fn finding_at(
    rule_id: &str,
    file_path: &str,
    line: u32,
    severity: Severity,
    message: &str,
) -> Finding {
    Finding::new_tool(
        "android-apk",
        rule_id,
        file_path,
        line,
        None,
        severity,
        message.to_string(),
    )
}

fn manifest_scan_output(
    inputs: &ManifestScanInputs,
    manifest: &ParsedManifest,
    findings: Vec<Finding>,
    persisted: Option<GenericPersistedRun>,
    taint_summary: TaintSourcesSummary,
) -> Value {
    let summary = format!(
        "android-apk:manifest-scan: {} findings from {} ({} taint sources written)",
        findings.len(),
        inputs.manifest_path.display(),
        taint_summary.count
    );
    json!({
        "ok": true,
        "summary": summary,
        "output": summary,
        "data": {
            "manifestPath": inputs.manifest_path.display().to_string(),
            "taintSourcesPath": taint_summary.path,
            "taintSourcesCount": taint_summary.count,
            "package": manifest.package,
            "targetSdk": manifest.target_sdk,
            "componentCount": manifest.components.len(),
            "permissionCount": manifest.permissions.len(),
            "findings": findings,
            "persisted": persisted,
        },
        "warnings": [],
        "errors": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const SAMPLE_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <uses-sdk android:targetSdkVersion="33"/>
    <application android:debuggable="true" android:allowBackup="true"
                 android:usesCleartextTraffic="true">
        <activity android:name=".LaunchActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="lyft" android:host="ride"/>
            </intent-filter>
        </activity>
        <provider android:name=".Provider" android:exported="true"/>
    </application>
</manifest>"#;

    fn parsed_sample() -> ParsedManifest {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AndroidManifest.xml");
        fs::write(&path, SAMPLE_MANIFEST).unwrap();
        parse_manifest_file(&path).unwrap()
    }

    #[test]
    fn application_flag_findings_cover_each_dangerous_attr() {
        let manifest = parsed_sample();
        let findings = check_application_flags(&manifest, "AndroidManifest.xml");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"android-apk:debuggable-true"));
        assert!(ids.contains(&"android-apk:allow-backup-true"));
        assert!(ids.contains(&"android-apk:cleartext-traffic"));
    }

    #[test]
    fn exported_activity_without_permission_flagged() {
        let manifest = parsed_sample();
        let findings = check_components(&manifest, "AndroidManifest.xml");
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "android-apk:exported-activity-no-permission"));
    }

    #[test]
    fn provider_exported_without_grant_flagged() {
        let manifest = parsed_sample();
        let findings = check_components(&manifest, "AndroidManifest.xml");
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "android-apk:provider-exported-no-grant"));
    }

    #[test]
    fn deeplink_finding_includes_schemes_and_hosts() {
        let manifest = parsed_sample();
        let findings = check_deeplinks(&manifest, "AndroidManifest.xml");
        let deeplink = findings
            .iter()
            .find(|f| f.rule_id == "android-apk:browseable-deeplink")
            .expect("deeplink finding");
        assert!(deeplink.message.contains("lyft"));
        assert!(deeplink.message.contains("ride"));
    }
}
