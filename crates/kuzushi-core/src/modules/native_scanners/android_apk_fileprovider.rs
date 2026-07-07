use super::*;

use crate::findings::Severity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::fs;
use std::path::{Path, PathBuf};

pub(in crate::modules) fn run_fileprovider_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_fileprovider_step(ctx, "tool", "fileprovider-scan start", &target, None);
    let scan = match scan_fileprovider_inputs(&input, &target) {
        Ok(scan) => scan,
        Err(error) => return Ok(fileprovider_failed_output(&target, error)),
    };
    let persisted = persist_tool_findings(
        "android-apk",
        &target,
        &scan.findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    emit_fileprovider_step(
        ctx,
        "done",
        "fileprovider-scan complete",
        &target,
        Some(scan.findings.len()),
    );
    Ok(fileprovider_output(
        &scan.inputs.file_paths,
        &scan.descriptors,
        scan.findings,
        persisted,
    ))
}

struct FileProviderInputs {
    file_paths: PathBuf,
}

struct FileProviderScan {
    inputs: FileProviderInputs,
    descriptors: Vec<PathDescriptor>,
    findings: Vec<Finding>,
}

fn scan_fileprovider_inputs(input: &Value, target: &Path) -> Result<FileProviderScan> {
    let inputs = resolve_fileprovider_inputs(input, target)?;
    let descriptors = collect_path_descriptors(&inputs.file_paths)?;
    let findings = fileprovider_findings(&descriptors, &inputs.file_paths);
    Ok(FileProviderScan {
        inputs,
        descriptors,
        findings,
    })
}

fn fileprovider_failed_output(target: &Path, error: anyhow::Error) -> Value {
    failed_tool_output("android-apk:fileprovider-scan", target, error)
}

fn emit_fileprovider_step(
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

fn resolve_fileprovider_inputs(input: &Value, workspace_root: &Path) -> Result<FileProviderInputs> {
    if let Some(raw) = input
        .get("filePathsPath")
        .or_else(|| input.get("file_paths_path"))
        .and_then(Value::as_str)
    {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok(FileProviderInputs { file_paths: path });
        }
    }
    let candidate = workspace_root
        .join("android-decompiled")
        .join("apktool")
        .join("res")
        .join("xml")
        .join("file_paths.xml");
    if !candidate.is_file() {
        anyhow::bail!(
            "android-apk:fileprovider-scan: missing {}. The APK may not declare a FileProvider, or apktool decode hasn't run yet.",
            candidate.display()
        );
    }
    Ok(FileProviderInputs {
        file_paths: candidate,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::modules) struct PathDescriptor {
    pub(in crate::modules) tag: String,
    pub(in crate::modules) name: Option<String>,
    pub(in crate::modules) path: Option<String>,
}

impl PathDescriptor {
    pub(in crate::modules) fn risk_level(&self) -> Severity {
        if self.is_root_export() {
            return Severity::Critical;
        }
        if self.is_broad_external() {
            return Severity::High;
        }
        if self.tag == "external-cache-path" {
            return Severity::Medium;
        }
        Severity::Info
    }

    fn is_root_export(&self) -> bool {
        if self.tag == "root-path" {
            return self.path.as_deref().map(is_root_like).unwrap_or(true);
        }
        false
    }

    fn is_broad_external(&self) -> bool {
        if !matches!(
            self.tag.as_str(),
            "external-path" | "external-files-path" | "external-media-path"
        ) {
            return false;
        }
        self.path.as_deref().map(is_root_like).unwrap_or(false)
    }
}

fn is_root_like(path: &str) -> bool {
    matches!(path.trim(), "" | "." | "/" | "./")
}

fn collect_path_descriptors(path: &Path) -> Result<Vec<PathDescriptor>> {
    let bytes = fs::read(path)
        .map_err(|error| anyhow::anyhow!("could not read {}: {error}", path.display()))?;
    parse_path_descriptors(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid XML in {}: {error}", path.display()))
}

fn parse_path_descriptors(bytes: &[u8]) -> Result<Vec<PathDescriptor>> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut descriptors = Vec::new();
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(start) | Event::Empty(start) => {
                if let Some(descriptor) = descriptor_for(&start)? {
                    descriptors.push(descriptor);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(descriptors)
}

fn descriptor_for(element: &BytesStart<'_>) -> Result<Option<PathDescriptor>> {
    let tag = local_name(element);
    if !is_descriptor_tag(&tag) {
        return Ok(None);
    }
    Ok(Some(PathDescriptor {
        tag,
        name: attr_value(element, "android:name")?,
        path: attr_value(element, "android:path")?,
    }))
}

fn is_descriptor_tag(tag: &str) -> bool {
    matches!(
        tag,
        "root-path"
            | "files-path"
            | "cache-path"
            | "external-path"
            | "external-files-path"
            | "external-cache-path"
            | "external-media-path"
    )
}

fn fileprovider_findings(descriptors: &[PathDescriptor], file_paths: &Path) -> Vec<Finding> {
    let path = file_paths.display().to_string();
    descriptors
        .iter()
        .filter_map(|descriptor| descriptor_finding(descriptor, &path))
        .collect()
}

fn descriptor_finding(descriptor: &PathDescriptor, file_paths: &str) -> Option<Finding> {
    let severity = descriptor.risk_level();
    if matches!(severity, Severity::Info) {
        return None;
    }
    let path_label = descriptor.path.clone().unwrap_or_else(|| "<empty>".into());
    let name_label = descriptor
        .name
        .clone()
        .unwrap_or_else(|| "<unnamed>".into());
    let message = format!(
        "FileProvider {} exposes broad path (name={:?}, path={:?}) (CWE-552). Attacker apps with the right URI grant can read user files.",
        descriptor.tag, name_label, path_label
    );
    Some(Finding::new_tool(
        "android-apk",
        &format!("android-apk:fileprovider-{}", descriptor.tag),
        file_paths,
        1,
        None,
        severity,
        message,
    ))
}

fn fileprovider_output(
    file_paths: &Path,
    descriptors: &[PathDescriptor],
    findings: Vec<Finding>,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    let summary = format!(
        "android-apk:fileprovider-scan: {} findings (descriptors={})",
        findings.len(),
        descriptors.len()
    );
    json!({
        "ok": true,
        "summary": summary,
        "output": summary,
        "data": {
            "filePathsPath": file_paths.display().to_string(),
            "descriptors": descriptors.iter().map(|d| json!({
                "tag": d.tag,
                "name": d.name,
                "path": d.path,
            })).collect::<Vec<_>>(),
            "findings": findings,
            "persisted": persisted,
        },
        "warnings": [],
        "errors": [],
    })
}

fn local_name(element: &BytesStart<'_>) -> String {
    let name = String::from_utf8_lossy(element.name().as_ref()).to_string();
    name.rsplit_once(':')
        .map(|(_, local)| local.to_string())
        .unwrap_or(name)
}

fn attr_value(element: &BytesStart<'_>, qualified: &str) -> Result<Option<String>> {
    for attr in element.attributes() {
        let attr = attr?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        if key == qualified || strip_ns(&key) == strip_ns(qualified) {
            return Ok(Some(
                String::from_utf8_lossy(attr.value.as_ref()).to_string(),
            ));
        }
    }
    Ok(None)
}

fn strip_ns(name: &str) -> &str {
    name.rsplit_once(':').map(|(_, l)| l).unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <root-path name="full-fs" path="."/>
    <external-path name="external" path="."/>
    <external-cache-path name="cache" path="."/>
    <files-path name="docs" path="documents/"/>
</paths>"#;

    fn descriptors() -> Vec<PathDescriptor> {
        parse_path_descriptors(SAMPLE.as_bytes()).unwrap()
    }

    #[test]
    fn parser_collects_all_known_tags() {
        let descriptors = descriptors();
        let tags: Vec<&str> = descriptors.iter().map(|d| d.tag.as_str()).collect();
        assert!(tags.contains(&"root-path"));
        assert!(tags.contains(&"external-path"));
        assert!(tags.contains(&"external-cache-path"));
        assert!(tags.contains(&"files-path"));
    }

    #[test]
    fn root_path_with_root_like_value_flagged_critical() {
        let descriptor = PathDescriptor {
            tag: "root-path".into(),
            name: None,
            path: Some(".".into()),
        };
        assert_eq!(descriptor.risk_level(), Severity::Critical);
    }

    #[test]
    fn external_path_with_broad_value_flagged_high() {
        let descriptor = PathDescriptor {
            tag: "external-path".into(),
            name: None,
            path: Some(".".into()),
        };
        assert_eq!(descriptor.risk_level(), Severity::High);
    }

    #[test]
    fn files_path_with_specific_directory_is_info() {
        let descriptor = PathDescriptor {
            tag: "files-path".into(),
            name: None,
            path: Some("documents/".into()),
        };
        assert_eq!(descriptor.risk_level(), Severity::Info);
    }

    #[test]
    fn findings_include_root_and_external_but_skip_specific_dirs() {
        let descriptors = descriptors();
        let findings = fileprovider_findings(&descriptors, std::path::Path::new("file_paths.xml"));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.iter().any(|id| id.contains("root-path")));
        assert!(ids.iter().any(|id| id.contains("external-path")));
        assert!(!ids.iter().any(|id| id.contains("files-path")));
    }

    #[test]
    fn parse_path_descriptors_reads_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file_paths.xml");
        fs::write(&path, SAMPLE).unwrap();
        let descriptors = collect_path_descriptors(&path).unwrap();
        assert!(descriptors.len() >= 4);
    }
}
