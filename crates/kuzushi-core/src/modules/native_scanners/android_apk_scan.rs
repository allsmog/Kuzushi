use super::*;

use std::path::Path;
use std::time::Instant;

pub(in crate::modules) fn run_android_apk_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let started = Instant::now();
    emit_step(ctx, "tool", "scan", &format!("android-apk:scan start · workspace={}", target.display()));
    let plan = match ScanPlan::from_input(&input, &target) {
        Ok(plan) => plan,
        Err(error) => return Ok(failed_tool_output("android-apk:scan", &target, error)),
    };
    let prepare_outcome = run_prepare_stage(&plan, ctx)?;
    if !stage_ok(&prepare_outcome) {
        return Ok(early_exit_output(&target, "prepare", prepare_outcome, started));
    }
    let stage_results = run_scan_stages(&plan, ctx);
    emit_step(
        ctx,
        "done",
        "scan",
        &format!("android-apk:scan complete · {} stages", stage_results.len() + 1),
    );
    Ok(scan_pipeline_output(
        &plan,
        prepare_outcome,
        stage_results,
        started,
    ))
}

#[derive(Debug)]
struct ScanPlan {
    apk_input: Value,
    workspace_input: Value,
    skip_native: bool,
    skip_code: bool,
    skip_hybrid: bool,
}

impl ScanPlan {
    fn from_input(input: &Value, target: &Path) -> Result<Self> {
        let apk = input
            .get("apk")
            .or_else(|| input.get("apkPath"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("android-apk:scan requires 'apk': path to the .apk file")
            })?;
        let decompiler = input
            .get("decompiler")
            .and_then(Value::as_str)
            .unwrap_or("both")
            .to_string();
        let apk_input = json!({
            "apk": apk,
            "decompiler": decompiler,
            "target": target.display().to_string(),
        });
        let workspace_input = json!({"target": target.display().to_string()});
        Ok(Self {
            apk_input,
            workspace_input,
            skip_native: read_skip_flag(input, "skipNative"),
            skip_code: read_skip_flag(input, "skipCode") || read_skip_flag(input, "skipWebview"),
            skip_hybrid: read_skip_flag(input, "skipHybrid"),
        })
    }
}

fn read_skip_flag(input: &Value, key: &str) -> bool {
    input.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn run_prepare_stage(plan: &ScanPlan, ctx: &ToolExecutionContext<'_>) -> Result<StageOutcome> {
    let value = run_android_apk_prepare(plan.apk_input.clone(), ctx)?;
    Ok(StageOutcome {
        name: "prepare",
        value,
    })
}

fn run_scan_stages(plan: &ScanPlan, ctx: &ToolExecutionContext<'_>) -> Vec<StageOutcome> {
    let mut stages: Vec<StageOutcome> = Vec::new();
    push_stage(&mut stages, "manifest-scan", run_manifest_scan(plan.workspace_input.clone(), ctx));
    push_stage(
        &mut stages,
        "network-security-config",
        run_network_security_config_scan(plan.workspace_input.clone(), ctx),
    );
    push_stage(
        &mut stages,
        "fileprovider-scan",
        run_fileprovider_scan(plan.workspace_input.clone(), ctx),
    );
    if !plan.skip_code {
        push_stage(&mut stages, "code-scan", run_code_scan(plan.workspace_input.clone(), ctx));
    }
    if !plan.skip_native {
        push_stage(&mut stages, "native-libs", run_native_libs_scan(plan.workspace_input.clone(), ctx));
    }
    if !plan.skip_hybrid {
        push_stage(&mut stages, "hybrid-detect", run_hybrid_detect(plan.workspace_input.clone(), ctx));
    }
    push_stage(
        &mut stages,
        "sast-handoff",
        run_sast_handoff(plan.workspace_input.clone(), ctx),
    );
    stages
}

fn push_stage(stages: &mut Vec<StageOutcome>, name: &'static str, result: Result<Value>) {
    match result {
        Ok(value) => stages.push(StageOutcome { name, value }),
        Err(error) => stages.push(StageOutcome {
            name,
            value: json!({
                "ok": false,
                "errors": [error.to_string()],
            }),
        }),
    }
}

struct StageOutcome {
    name: &'static str,
    value: Value,
}

fn stage_ok(stage: &StageOutcome) -> bool {
    stage.value.get("ok").and_then(Value::as_bool).unwrap_or(false)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}

fn scan_pipeline_output(
    plan: &ScanPlan,
    prepare: StageOutcome,
    scans: Vec<StageOutcome>,
    started: Instant,
) -> Value {
    let all_stages: Vec<StageOutcome> = std::iter::once(prepare).chain(scans).collect();
    let totals = aggregate_totals(&all_stages);
    let stages_value: Vec<Value> = all_stages.iter().map(stage_to_json).collect();
    let warnings: Vec<Value> = all_stages
        .iter()
        .filter(|stage| !stage_ok(stage))
        .map(stage_warning)
        .collect();
    let summary = format!(
        "android-apk:scan: {} stages, {} findings, {} skipped, {}ms",
        stages_value.len(),
        totals.findings,
        warnings.len(),
        started.elapsed().as_millis()
    );
    json!({
        "ok": true,
        "summary": summary,
        "output": summary,
        "data": {
            "apk": plan.apk_input.get("apk"),
            "stages": stages_value,
            "totals": {
                "stagesRun": all_stages.len(),
                "skipped": warnings.len(),
                "findings": totals.findings,
            },
        },
        "warnings": warnings,
        "errors": [],
    })
}

fn stage_warning(stage: &StageOutcome) -> Value {
    let primary_error = stage
        .value
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .cloned()
        .unwrap_or_else(|| Value::String(format!("{} did not produce results", stage.name)));
    json!({
        "stage": stage.name,
        "reason": primary_error,
    })
}

fn early_exit_output(
    target: &Path,
    failed_stage: &str,
    prepare: StageOutcome,
    started: Instant,
) -> Value {
    let errors = prepare
        .value
        .get("errors")
        .cloned()
        .unwrap_or_else(|| json!([format!("{failed_stage} failed")]));
    let _ = target;
    json!({
        "ok": false,
        "summary": format!(
            "android-apk:scan aborted at {failed_stage} ({}ms)",
            started.elapsed().as_millis()
        ),
        "output": format!("android-apk:scan aborted at {failed_stage}"),
        "data": {
            "stages": [stage_to_json(&prepare)],
            "failedStage": failed_stage,
        },
        "warnings": [],
        "errors": errors,
    })
}

#[derive(Default)]
struct PipelineTotals {
    findings: usize,
    failures: usize,
}

fn aggregate_totals(stages: &[StageOutcome]) -> PipelineTotals {
    let mut totals = PipelineTotals::default();
    for stage in stages {
        if !stage_ok(stage) {
            totals.failures += 1;
        }
        totals.findings += stage_findings_array(&stage.value).len();
    }
    totals
}

fn stage_to_json(stage: &StageOutcome) -> Value {
    let stage_findings = stage_findings_array(&stage.value);
    json!({
        "name": stage.name,
        "ok": stage_ok(stage),
        "summary": stage.value.get("summary").cloned().unwrap_or(Value::Null),
        "findings": stage_findings.len(),
        "findingItems": stage_findings,
        "errors": stage.value.get("errors").cloned().unwrap_or(json!([])),
    })
}

fn stage_findings_array(value: &Value) -> Vec<Value> {
    value.pointer("/data/findings").and_then(Value::as_array).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(name: &'static str, ok: bool, findings: usize) -> StageOutcome {
        let payload = json!({
            "ok": ok,
            "summary": format!("{name} ran"),
            "data": {
                "findings": (0..findings).map(|i| json!({"rule_id": format!("r{i}")})).collect::<Vec<_>>(),
            },
            "errors": if ok { json!([]) } else { json!(["boom"]) },
        });
        StageOutcome { name, value: payload }
    }

    #[test]
    fn aggregate_totals_counts_findings_and_failures() {
        let stages = vec![
            stage("prepare", true, 0),
            stage("manifest-scan", true, 5),
            stage("code-scan", false, 0),
            stage("native-libs", true, 2),
        ];
        let totals = aggregate_totals(&stages);
        assert_eq!(totals.findings, 7);
        assert_eq!(totals.failures, 1);
    }

    #[test]
    fn stage_to_json_carries_summary_and_findings_count() {
        let outcome = stage("manifest-scan", true, 3);
        let payload = stage_to_json(&outcome);
        assert_eq!(payload["name"], "manifest-scan");
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["findings"], 3);
    }

    #[test]
    fn plan_rejects_missing_apk() {
        let target = std::path::PathBuf::from("/tmp/ws");
        let error = ScanPlan::from_input(&json!({}), &target).expect_err("missing apk rejected");
        assert!(error.to_string().contains("requires 'apk'"));
    }

    #[test]
    fn plan_accepts_apkPath_alias_and_skip_flags() {
        let target = std::path::PathBuf::from("/tmp/ws");
        let input = json!({
            "apkPath": "./app.apk",
            "decompiler": "jadx",
            "skipNative": true,
            "skipCode": true,
        });
        let plan = ScanPlan::from_input(&input, &target).unwrap();
        assert_eq!(plan.apk_input.get("apk"), Some(&Value::String("./app.apk".into())));
        assert_eq!(plan.apk_input.get("decompiler"), Some(&Value::String("jadx".into())));
        assert!(plan.skip_native);
        assert!(plan.skip_code);
        assert!(!plan.skip_hybrid);
    }

    #[test]
    fn plan_skip_webview_alias_still_works() {
        let target = std::path::PathBuf::from("/tmp/ws");
        let input = json!({"apk": "./app.apk", "skipWebview": true});
        let plan = ScanPlan::from_input(&input, &target).unwrap();
        assert!(plan.skip_code);
    }
}
