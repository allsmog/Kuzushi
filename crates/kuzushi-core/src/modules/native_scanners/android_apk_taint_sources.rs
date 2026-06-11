use super::*;

use std::fs;
use std::path::Path;

pub(in crate::modules) struct TaintSourcesSummary {
    pub(in crate::modules) path: String,
    pub(in crate::modules) count: usize,
}

pub(in crate::modules) fn write_taint_sources(
    manifest: &ParsedManifest,
    path: &Path,
) -> Result<TaintSourcesSummary> {
    let sources = build_taint_sources(manifest);
    let payload = json!({
        "package": manifest.package,
        "sources": sources,
    });
    fs::write(path, serde_json::to_string_pretty(&payload)?)
        .map_err(|error| anyhow::anyhow!("could not write {}: {error}", path.display()))?;
    Ok(TaintSourcesSummary {
        path: path.display().to_string(),
        count: sources.len(),
    })
}

pub(in crate::modules) fn build_taint_sources(manifest: &ParsedManifest) -> Vec<Value> {
    manifest
        .components
        .iter()
        .filter(|component| component.is_effectively_exported())
        .map(|component| taint_source_entry(component))
        .collect()
}

fn taint_source_entry(component: &Component) -> Value {
    let (schemes, hosts) = collect_deeplink_metadata(component);
    json!({
        "kind": format!("exported-{}", component.kind.label()),
        "componentName": component.name,
        "permission": component.permission,
        "deeplinkSchemes": schemes,
        "deeplinkHosts": hosts,
    })
}

fn collect_deeplink_metadata(component: &Component) -> (Vec<String>, Vec<String>) {
    let mut schemes = Vec::new();
    let mut hosts = Vec::new();
    for filter in &component.intent_filters {
        schemes.extend(filter.schemes.iter().cloned());
        hosts.extend(filter.hosts.iter().cloned());
    }
    schemes.sort();
    schemes.dedup();
    hosts.sort();
    hosts.dedup();
    (schemes, hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application>
        <activity android:name=".A" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="lyft" android:host="ride"/>
            </intent-filter>
        </activity>
        <service android:name=".S" android:exported="false"/>
    </application>
</manifest>"#;

    fn parsed() -> ParsedManifest {
        let dir = tempdir().unwrap();
        let path = dir.path().join("AndroidManifest.xml");
        fs::write(&path, SAMPLE).unwrap();
        parse_manifest_file(&path).unwrap()
    }

    #[test]
    fn build_taint_sources_only_includes_exported() {
        let manifest = parsed();
        let sources = build_taint_sources(&manifest);
        assert_eq!(sources.len(), 1);
        let kind = sources[0].get("kind").and_then(Value::as_str).unwrap();
        assert!(kind.contains("exported-activity"));
    }

    #[test]
    fn taint_entry_includes_schemes_and_hosts() {
        let manifest = parsed();
        let sources = build_taint_sources(&manifest);
        let schemes = sources[0].get("deeplinkSchemes").unwrap();
        let hosts = sources[0].get("deeplinkHosts").unwrap();
        assert_eq!(schemes, &json!(["lyft"]));
        assert_eq!(hosts, &json!(["ride"]));
    }

    #[test]
    fn write_taint_sources_writes_json_payload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ts.json");
        let manifest = parsed();
        let summary = write_taint_sources(&manifest, &path).unwrap();
        assert_eq!(summary.count, 1);
        let payload = fs::read_to_string(&path).unwrap();
        assert!(payload.contains("\"package\": \"com.example.app\""));
        assert!(payload.contains("exported-activity"));
    }
}
