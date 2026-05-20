use super::*;

use crate::findings::Severity;
use std::path::{Path, PathBuf};

pub(in crate::modules) fn run_hybrid_detect(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_step(ctx, "tool", "scan", &format!("hybrid-detect start · target={}", target.display()));
    let outcome = match detect_hybrid_frameworks(&input, &target) {
        Ok(outcome) => outcome,
        Err(error) => return Ok(failed_tool_output("android-apk:hybrid-detect", &target, error)),
    };
    let persisted = persist_tool_findings(
        "android-apk",
        &target,
        &outcome.findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    emit_step(ctx, "done", "scan", &format!("hybrid-detect complete · frameworks={:?}", outcome.detected));
    Ok(hybrid_detect_output(&outcome, persisted))
}

struct HybridDetection {
    raw_root: PathBuf,
    detected: Vec<String>,
    evidence: Vec<HybridEvidence>,
    findings: Vec<Finding>,
}

#[derive(Debug)]
struct HybridEvidence {
    framework: String,
    indicator_path: PathBuf,
}

fn detect_hybrid_frameworks(input: &Value, workspace_root: &Path) -> Result<HybridDetection> {
    let raw_root = resolve_raw_root(input, workspace_root)?;
    let probes = probe_frameworks(&raw_root);
    let detected = probes
        .iter()
        .map(|evidence| evidence.framework.clone())
        .collect::<Vec<_>>();
    let findings = probes.iter().map(hybrid_finding).collect();
    Ok(HybridDetection {
        raw_root,
        detected,
        evidence: probes,
        findings,
    })
}

fn resolve_raw_root(input: &Value, workspace_root: &Path) -> Result<PathBuf> {
    if let Some(raw) = input
        .get("rawRoot")
        .or_else(|| input.get("raw_root"))
        .and_then(Value::as_str)
    {
        let path = PathBuf::from(raw);
        if path.is_dir() {
            return Ok(path);
        }
    }
    let candidate = workspace_root.join("android-decompiled").join("raw");
    if !candidate.is_dir() {
        anyhow::bail!(
            "android-apk:hybrid-detect: missing {}. Run `android-apk:prepare` first.",
            candidate.display()
        );
    }
    Ok(candidate)
}

fn probe_frameworks(raw_root: &Path) -> Vec<HybridEvidence> {
    HYBRID_PROBES
        .iter()
        .flat_map(|probe| probe_one(raw_root, probe))
        .collect()
}

fn probe_one(raw_root: &Path, probe: &FrameworkProbe) -> Vec<HybridEvidence> {
    probe
        .indicators
        .iter()
        .filter_map(|relative| {
            let path = raw_root.join(relative);
            path.exists().then(|| HybridEvidence {
                framework: probe.name.to_string(),
                indicator_path: path,
            })
        })
        .collect()
}

struct FrameworkProbe {
    name: &'static str,
    indicators: &'static [&'static str],
}

const HYBRID_PROBES: &[FrameworkProbe] = &[
    FrameworkProbe {
        name: "Cordova",
        indicators: &[
            "assets/www/cordova.js",
            "assets/www/cordova_plugins.js",
            "assets/www/plugins",
        ],
    },
    FrameworkProbe {
        name: "React Native",
        indicators: &["assets/index.android.bundle"],
    },
    FrameworkProbe {
        name: "Capacitor",
        indicators: &[
            "assets/public/capacitor.config.json",
            "assets/capacitor.config.json",
        ],
    },
    FrameworkProbe {
        name: "Flutter",
        indicators: &[
            "assets/flutter_assets/AssetManifest.json",
            "assets/flutter_assets/kernel_blob.bin",
        ],
    },
    FrameworkProbe {
        name: "Ionic",
        indicators: &[
            "assets/public/index.html",
            "assets/public/build/index.esm.js",
        ],
    },
];

fn hybrid_finding(evidence: &HybridEvidence) -> Finding {
    let path = evidence.indicator_path.display().to_string();
    let message = format!(
        "Detected {} hybrid app via {} (CWE-915-adjacent attack surface). Audit the JavaScript bundle for hardcoded secrets, insecure URL loading, and JS-bridge methods that touch sensitive APIs from the device side. Lyft's apps and other production Android targets often embed React Native / Cordova partials behind native shells.",
        evidence.framework, evidence.indicator_path.display()
    );
    Finding::new_tool(
        "android-apk",
        &format!("android-apk:hybrid-{}", evidence.framework.to_lowercase().replace(' ', "-")),
        &path,
        1,
        None,
        Severity::Info,
        message,
    )
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}

fn hybrid_detect_output(
    outcome: &HybridDetection,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    let summary = if outcome.detected.is_empty() {
        format!(
            "android-apk:hybrid-detect: no Cordova/React Native/Capacitor/Flutter/Ionic indicators under {}",
            outcome.raw_root.display()
        )
    } else {
        format!(
            "android-apk:hybrid-detect: detected {:?} hybrid framework(s) under {}",
            unique(&outcome.detected),
            outcome.raw_root.display()
        )
    };
    json!({
        "ok": true,
        "summary": summary,
        "output": summary,
        "data": {
            "rawRoot": outcome.raw_root.display().to_string(),
            "detectedFrameworks": unique(&outcome.detected),
            "evidence": outcome.evidence.iter().map(|e| json!({
                "framework": e.framework,
                "indicatorPath": e.indicator_path.display().to_string(),
            })).collect::<Vec<_>>(),
            "findings": outcome.findings,
            "persisted": persisted,
        },
        "warnings": [],
        "errors": [],
    })
}

fn unique(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = values.to_vec();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn make_raw(files: &[&str]) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let raw = dir.path().join("android-decompiled/raw");
        for file in files {
            let path = raw.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "stub").unwrap();
        }
        dir
    }

    #[test]
    fn detects_cordova_indicator() {
        let dir = make_raw(&["assets/www/cordova.js"]);
        let outcome = detect_hybrid_frameworks(&json!({}), dir.path()).unwrap();
        assert!(outcome.detected.contains(&"Cordova".to_string()));
    }

    #[test]
    fn detects_react_native_bundle() {
        let dir = make_raw(&["assets/index.android.bundle"]);
        let outcome = detect_hybrid_frameworks(&json!({}), dir.path()).unwrap();
        assert!(outcome.detected.contains(&"React Native".to_string()));
    }

    #[test]
    fn detects_capacitor_config() {
        let dir = make_raw(&["assets/public/capacitor.config.json"]);
        let outcome = detect_hybrid_frameworks(&json!({}), dir.path()).unwrap();
        assert!(outcome.detected.contains(&"Capacitor".to_string()));
    }

    #[test]
    fn detects_flutter_assets() {
        let dir = make_raw(&["assets/flutter_assets/AssetManifest.json"]);
        let outcome = detect_hybrid_frameworks(&json!({}), dir.path()).unwrap();
        assert!(outcome.detected.contains(&"Flutter".to_string()));
    }

    #[test]
    fn no_indicators_returns_empty_detection() {
        let dir = make_raw(&["assets/values/strings.xml"]);
        let outcome = detect_hybrid_frameworks(&json!({}), dir.path()).unwrap();
        assert!(outcome.detected.is_empty());
        assert!(outcome.findings.is_empty());
    }

    #[test]
    fn unique_dedupes_repeated_frameworks() {
        let values = vec!["Cordova".into(), "Cordova".into(), "Flutter".into()];
        let deduped = unique(&values);
        assert_eq!(deduped, vec!["Cordova".to_string(), "Flutter".to_string()]);
    }
}
