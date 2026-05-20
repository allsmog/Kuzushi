use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn format_android_apk_scan_plain(envelope: &Value) -> Option<String> {
    let data = envelope.get("data")?;
    let stages = data.get("stages")?.as_array()?;
    let totals = data.get("totals")?;
    let mut out = String::new();
    out.push_str(&format_header(envelope, totals));
    out.push('\n');
    out.push('\n');
    out.push_str(&format_stage_table(stages));
    if let Some(top) = format_top_findings(stages) {
        out.push('\n');
        out.push_str(&top);
    }
    if let Some(warnings) = format_warnings_block(envelope) {
        out.push('\n');
        out.push_str(&warnings);
    }
    out.push('\n');
    out.push_str("next: kuzushi findings --severity high,critical\n");
    Some(out)
}

fn format_header(envelope: &Value, totals: &Value) -> String {
    let findings = totals
        .get("findings")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let stages = totals
        .get("stagesRun")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let skipped = totals
        .get("skipped")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let apk = envelope
        .get("data")
        .and_then(|d| d.get("apk"))
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    format!(
        "android-apk:scan {}\n  {} findings · {} stages · {} skipped",
        apk, findings, stages, skipped
    )
}

fn format_stage_table(stages: &[Value]) -> String {
    let mut out = String::from("stages:\n");
    for stage in stages {
        out.push_str(&format_stage_row(stage));
        out.push('\n');
    }
    out
}

fn format_stage_row(stage: &Value) -> String {
    let name = stage.get("name").and_then(Value::as_str).unwrap_or("?");
    let ok = stage.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let marker = if ok { "+" } else { "-" };
    let findings = stage.get("findings").and_then(Value::as_u64).unwrap_or(0);
    let detail = if ok {
        format!("{} findings", findings)
    } else {
        stage_skip_reason(stage)
    };
    format!("  {} {:<28} {}", marker, name, detail)
}

fn stage_skip_reason(stage: &Value) -> String {
    stage
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_str)
        .map(short_skip_reason)
        .unwrap_or_else(|| "skipped".to_string())
}

fn short_skip_reason(message: &str) -> String {
    if message.contains("network_security_config.xml") {
        return "no network_security_config.xml".to_string();
    }
    if message.contains("file_paths.xml") {
        return "no file_paths.xml in res/xml".to_string();
    }
    if message.contains("native libraries") || message.contains("lib/") {
        return "no native lib/ directory".to_string();
    }
    truncate_message(message, 80)
}

fn truncate_message(message: &str, max: usize) -> String {
    let first_line = message.split('\n').next().unwrap_or(message).trim();
    if first_line.chars().count() <= max {
        return first_line.to_string();
    }
    let truncated: String = first_line.chars().take(max).collect();
    format!("{}…", truncated)
}

#[derive(Debug)]
struct FindingSummary {
    rule_id: String,
    severity: String,
    count: usize,
    sample_path: String,
}

fn format_top_findings(stages: &[Value]) -> Option<String> {
    let mut counts: BTreeMap<(String, String), FindingSummary> = BTreeMap::new();
    for stage in stages {
        collect_findings_from_stage(stage, &mut counts);
    }
    if counts.is_empty() {
        return None;
    }
    let mut ranked: Vec<FindingSummary> = counts.into_values().collect();
    ranked.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));
    let mut out = String::from("top findings:\n");
    for (idx, summary) in ranked.iter().take(10).enumerate() {
        out.push_str(&format_finding_row(idx + 1, summary));
        out.push('\n');
    }
    Some(out)
}

fn collect_findings_from_stage(
    stage: &Value,
    counts: &mut BTreeMap<(String, String), FindingSummary>,
) {
    let findings = match stage_finding_array(stage) {
        Some(array) => array,
        None => return,
    };
    for finding in findings {
        let rule_id = finding
            .get("rule_id")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_string();
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string();
        let file_path = finding
            .get("file_path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let key = (severity.clone(), rule_id.clone());
        let entry = counts.entry(key).or_insert_with(|| FindingSummary {
            rule_id: rule_id.clone(),
            severity: severity.clone(),
            count: 0,
            sample_path: file_path.clone(),
        });
        entry.count += 1;
    }
}

fn stage_finding_array(stage: &Value) -> Option<&Vec<Value>> {
    stage
        .get("findingItems")
        .and_then(Value::as_array)
        .or_else(|| {
            stage
                .get("data")
                .and_then(|d| d.get("findings"))
                .and_then(Value::as_array)
        })
        .or_else(|| stage.get("findings").and_then(Value::as_array))
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn severity_label(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "C",
        "high" => "H",
        "medium" => "M",
        "low" => "L",
        _ => "I",
    }
}

fn format_finding_row(index: usize, summary: &FindingSummary) -> String {
    let count_suffix = if summary.count > 1 {
        format!(" (x{})", summary.count)
    } else {
        String::new()
    };
    let path = path_for_display(&summary.sample_path);
    format!(
        "  {:>2}. [{}]  {:<48}{} {}",
        index,
        severity_label(&summary.severity),
        summary.rule_id,
        count_suffix,
        path
    )
}

fn path_for_display(path: &str) -> String {
    let basename = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    basename.to_string()
}

fn format_warnings_block(envelope: &Value) -> Option<String> {
    let warnings = envelope.get("warnings")?.as_array()?;
    if warnings.is_empty() {
        return None;
    }
    let mut out = String::from("warnings:\n");
    for warning in warnings.iter().take(5) {
        let stage = warning.get("stage").and_then(Value::as_str).unwrap_or("?");
        let reason = warning.get("reason").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("  - {}: {}\n", stage, short_skip_reason(reason)));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_envelope() -> Value {
        json!({
            "ok": true,
            "summary": "android-apk:scan: 8 stages, 22 findings, 3 skipped, 26000ms",
            "data": {
                "apk": "./InsecureBankv2.apk",
                "stages": [
                    {"name": "prepare", "ok": true, "findings": 0},
                    {"name": "manifest-scan", "ok": true, "findings": 10, "data": {"findings": [
                        {"rule_id": "android-apk:debuggable-true", "severity": "high", "file_path": "/x/AndroidManifest.xml"},
                        {"rule_id": "android-apk:exported-activity-no-permission", "severity": "high", "file_path": "/x/AndroidManifest.xml"},
                        {"rule_id": "android-apk:exported-activity-no-permission", "severity": "high", "file_path": "/x/AndroidManifest.xml"},
                        {"rule_id": "android-apk:allow-backup-true", "severity": "medium", "file_path": "/x/AndroidManifest.xml"},
                    ]}},
                    {"name": "network-security-config", "ok": false, "findings": 0, "errors": ["android-apk:network-security-config: missing /tmp/x/.../network_security_config.xml. Either …"]},
                    {"name": "code-scan", "ok": true, "findings": 0},
                ],
                "totals": {"findings": 22, "stagesRun": 8, "skipped": 3},
            },
            "warnings": [
                {"stage": "network-security-config", "reason": "android-apk:network-security-config: missing /tmp/x/.../network_security_config.xml. Either the APK has no network security config…"},
                {"stage": "fileprovider-scan", "reason": "android-apk:fileprovider-scan: missing /tmp/x/.../file_paths.xml. The APK may not declare a FileProvider…"},
            ],
        })
    }

    #[test]
    fn renders_header_with_apk_and_totals() {
        let formatted = format_android_apk_scan_plain(&sample_envelope()).unwrap();
        assert!(formatted.contains("InsecureBankv2.apk"));
        assert!(formatted.contains("22 findings"));
        assert!(formatted.contains("8 stages"));
        assert!(formatted.contains("3 skipped"));
    }

    #[test]
    fn renders_stage_table_with_markers() {
        let formatted = format_android_apk_scan_plain(&sample_envelope()).unwrap();
        assert!(formatted.contains("+ prepare"));
        assert!(formatted.contains("+ manifest-scan"));
        assert!(formatted.contains("- network-security-config"));
        assert!(formatted.contains("no network_security_config.xml"));
    }

    #[test]
    fn top_findings_groups_repeated_rules() {
        let formatted = format_android_apk_scan_plain(&sample_envelope()).unwrap();
        assert!(formatted.contains("top findings:"));
        assert!(formatted.contains("[H]  android-apk:debuggable-true"));
        assert!(formatted.contains("(x2)")); // exported-activity-no-permission appears twice
    }

    #[test]
    fn warnings_section_uses_short_reasons() {
        let formatted = format_android_apk_scan_plain(&sample_envelope()).unwrap();
        assert!(formatted.contains("warnings:"));
        assert!(formatted.contains("network-security-config"));
        assert!(formatted.contains("fileprovider-scan"));
    }

    #[test]
    fn returns_none_for_non_scan_envelope() {
        let value = json!({"ok": true, "output": "hello"});
        assert!(format_android_apk_scan_plain(&value).is_none());
    }

    #[test]
    fn next_step_hint_present() {
        let formatted = format_android_apk_scan_plain(&sample_envelope()).unwrap();
        assert!(formatted.contains("kuzushi findings --severity high,critical"));
    }
}
