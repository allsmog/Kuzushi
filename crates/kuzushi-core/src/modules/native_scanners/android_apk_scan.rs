use super::*;

use std::path::Path;
use std::time::Instant;

pub(in crate::modules) fn run_android_apk_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let started = Instant::now();
    emit_android_scan_start(ctx, &target);
    let primary_run_id = ctx
        .run_id()
        .or_else(|| string_input_any(&input, &["runId", "run_id"]))
        .unwrap_or_else(|| crate::run_artifacts::new_run_id("scan"));
    let mut plan = match ScanPlan::from_input(&input, &target, primary_run_id) {
        Ok(plan) => plan,
        Err(error) => return Ok(failed_tool_output("android-apk:scan", &target, error)),
    };
    let prepare_outcome = run_prepare_stage(&plan, ctx)?;
    if !stage_ok(&prepare_outcome) {
        return Ok(early_exit_output(
            &target,
            &plan.primary_run_id,
            "prepare",
            prepare_outcome,
            started,
        ));
    }
    plan.input_receipt = prepare_outcome.value.pointer("/data/inputReceipt").cloned();
    let mut stage_results = run_scan_stages(&plan, ctx);
    append_input_recheck(&mut stage_results, &plan, ctx);
    let failed_stages = stage_results
        .iter()
        .filter(|stage| !stage_ok(stage))
        .count();
    emit_android_scan_done(ctx, stage_results.len() + 1, failed_stages);
    Ok(scan_pipeline_output(
        &plan,
        prepare_outcome,
        stage_results,
        started,
    ))
}

#[derive(Debug)]
struct ScanPlan {
    primary_run_id: String,
    apk_input: Value,
    workspace_input: Value,
    input_receipt: Option<Value>,
    skip_native: bool,
    skip_code: bool,
    skip_hybrid: bool,
}

impl ScanPlan {
    fn from_input(input: &Value, target: &Path, primary_run_id: String) -> Result<Self> {
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
        let apk_input = preparation_input(input, apk, &decompiler, target);
        let workspace_input = scan_input(input, target);
        Ok(Self {
            primary_run_id,
            apk_input,
            workspace_input,
            input_receipt: None,
            skip_native: read_skip_flag(input, "skipNative"),
            skip_code: read_skip_flag(input, "skipCode") || read_skip_flag(input, "skipWebview"),
            skip_hybrid: read_skip_flag(input, "skipHybrid"),
        })
    }

    fn skipped_stage_count(&self) -> usize {
        [self.skip_code, self.skip_native, self.skip_hybrid]
            .into_iter()
            .filter(|skipped| *skipped)
            .count()
    }
}

fn preparation_input(input: &Value, apk: &str, decompiler: &str, target: &Path) -> Value {
    let mut value = json!({"apk":apk,"decompiler":decompiler,"target":target});
    for key in [
        "timeoutMs",
        "jadxBin",
        "apktoolBin",
        "unzipBin",
        "maxApkBytes",
    ] {
        if let Some(option) = input.get(key) {
            value[key] = option.clone();
        }
    }
    value
}

fn scan_input(input: &Value, target: &Path) -> Value {
    let mut value = json!({"target":target});
    for key in ["timeoutMs", "includeLibraries"] {
        if let Some(option) = input.get(key) {
            value[key] = option.clone();
        }
    }
    if let Some(binary) = input.get("semgrepBin") {
        value["binary"] = binary.clone();
    }
    value
}

fn append_input_recheck(
    stages: &mut Vec<StageOutcome>,
    plan: &ScanPlan,
    ctx: &ToolExecutionContext<'_>,
) {
    let value = plan.input_receipt.as_ref().unwrap_or(&Value::Null);
    let result =
        super::android_apk_input_receipt::ApkInputReceipt::from_value(value).and_then(|receipt| {
            ctx.with_cancellation(|cancel| receipt.require_unchanged(&plan.apk_input, cancel))
        });
    if let Err(error) = result {
        stages.push(StageOutcome { name:"input-check",value:json!({"ok":false,"status":"partial","summary":"APK input recheck failed; retained observations require review","errors":[format!("{error:#}")]}) });
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
    let mut stages = run_fixed_scan_stages(plan, ctx);
    push_optional_scan_stages(&mut stages, plan, ctx);
    push_stage(&mut stages, "sast-handoff", ctx, || {
        run_sast_handoff(plan.workspace_input.clone(), ctx)
    });
    stages
}

fn run_fixed_scan_stages(plan: &ScanPlan, ctx: &ToolExecutionContext<'_>) -> Vec<StageOutcome> {
    let mut stages = Vec::new();
    push_stage(&mut stages, "manifest-scan", ctx, || {
        run_manifest_scan(plan.workspace_input.clone(), ctx)
    });
    push_stage(&mut stages, "network-security-config", ctx, || {
        run_network_security_config_scan(plan.workspace_input.clone(), ctx)
    });
    push_stage(&mut stages, "fileprovider-scan", ctx, || {
        run_fileprovider_scan(plan.workspace_input.clone(), ctx)
    });
    stages
}

fn push_optional_scan_stages(
    stages: &mut Vec<StageOutcome>,
    plan: &ScanPlan,
    ctx: &ToolExecutionContext<'_>,
) {
    if !plan.skip_code {
        push_stage(stages, "code-scan", ctx, || {
            run_code_scan(plan.workspace_input.clone(), ctx)
        });
    }
    if !plan.skip_native {
        push_stage(stages, "native-libs", ctx, || {
            run_native_libs_scan(plan.workspace_input.clone(), ctx)
        });
    }
    if !plan.skip_hybrid {
        push_stage(stages, "hybrid-detect", ctx, || {
            run_hybrid_detect(plan.workspace_input.clone(), ctx)
        });
    }
}

fn push_stage(
    stages: &mut Vec<StageOutcome>,
    name: &'static str,
    ctx: &ToolExecutionContext<'_>,
    action: impl FnOnce() -> Result<Value>,
) {
    let result = ctx.with_cancellation(|cancel| {
        anyhow::ensure!(
            !cancel.is_cancelled(),
            "APK stage {name} was not started after cancellation"
        );
        action()
    });
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
    stage.value.get("status").and_then(Value::as_str) != Some("partial")
        && stage
            .value
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}

fn emit_android_scan_start(ctx: &ToolExecutionContext<'_>, target: &Path) {
    emit_step(
        ctx,
        "tool",
        "scan",
        &format!("android-apk:scan start · workspace={}", target.display()),
    );
}

fn emit_android_scan_done(
    ctx: &ToolExecutionContext<'_>,
    stage_count: usize,
    failed_stages: usize,
) {
    let outcome = if failed_stages == 0 {
        "complete".to_string()
    } else {
        format!("partial · {failed_stages} failed")
    };
    emit_step(
        ctx,
        if failed_stages == 0 { "done" } else { "warn" },
        "scan",
        &format!("android-apk:scan {outcome} · {stage_count} stages"),
    );
}

fn scan_pipeline_output(
    plan: &ScanPlan,
    prepare: StageOutcome,
    scans: Vec<StageOutcome>,
    started: Instant,
) -> Value {
    let all_stages: Vec<StageOutcome> = std::iter::once(prepare).chain(scans).collect();
    let projection = project_pipeline_output(plan, &all_stages, started);
    pipeline_output_json(plan, all_stages.len(), projection)
}

struct PipelineOutputProjection {
    stages: Vec<Value>,
    warnings: Vec<Value>,
    errors: Vec<Value>,
    run_ids: Vec<String>,
    findings: usize,
    failures: usize,
    skipped: usize,
    summary: String,
}

fn project_pipeline_output(
    plan: &ScanPlan,
    all_stages: &[StageOutcome],
    started: Instant,
) -> PipelineOutputProjection {
    let totals = aggregate_totals(&all_stages);
    let run_ids = pipeline_run_ids(&all_stages);
    let stages_value: Vec<Value> = all_stages.iter().map(stage_to_json).collect();
    let warnings: Vec<Value> = all_stages
        .iter()
        .filter(|stage| !stage_ok(stage))
        .map(stage_warning)
        .collect();
    let errors = all_stages
        .iter()
        .filter(|stage| !stage_ok(stage))
        .flat_map(stage_error_messages)
        .map(Value::String)
        .collect();
    let skipped = plan.skipped_stage_count();
    let summary = format!(
        "Partial APK observations · {} stages · findings {} · incomplete {} · skipped {} · {}ms",
        stages_value.len(),
        totals.findings,
        totals.failures,
        skipped,
        started.elapsed().as_millis()
    );
    PipelineOutputProjection {
        stages: stages_value,
        warnings,
        errors,
        run_ids,
        findings: totals.findings,
        failures: totals.failures,
        skipped,
        summary,
    }
}

fn pipeline_output_json(
    plan: &ScanPlan,
    stage_count: usize,
    output: PipelineOutputProjection,
) -> Value {
    let text = pipeline_output_text(plan, &output);
    let input_recheck = input_recheck_label(plan, &output);
    json!({
        "ok": true,
        "status": "partial",
        "summary": output.summary,
        "output": text,
        "data": {
            "runId": plan.primary_run_id,
            "runIds": output.run_ids,
            "apk": plan.apk_input.get("apk"),
            "inputReceipt": plan.input_receipt,
            "inputRecheck": input_recheck,
            "coverage": {"complete":false},
            "sourceVerified":false,
            "stages": output.stages,
            "totals": {
                "stagesRun": stage_count,
                "failed": output.failures,
                "skipped": output.skipped,
                "findings": output.findings,
            },
        },
        "warnings": output.warnings.into_iter().chain(std::iter::once(json!({"code":"partial-apk-coverage","message":"Decompilation and rule observations need independent review. Skipped or omitted code is not complete APK or repository coverage. No Scan checkpoint is created."}))).collect::<Vec<_>>(),
        "errors": output.errors,
    })
}

fn input_recheck_label(plan: &ScanPlan, output: &PipelineOutputProjection) -> &'static str {
    if plan.input_receipt.is_none() {
        return "missing";
    }
    if output
        .stages
        .iter()
        .any(|stage| stage["name"] == "input-check")
    {
        return "failed";
    }
    "matched"
}

fn pipeline_output_text(plan: &ScanPlan, output: &PipelineOutputProjection) -> String {
    let mut lines = vec![
        output.summary.clone(),
        "Coverage: partial decompiled observations; original-source accuracy requires review."
            .into(),
    ];
    if let Some(receipt) = plan.input_receipt.as_ref() {
        lines.push(format!(
            "Archive digest: {} · {} bytes",
            receipt["sha256"].as_str().unwrap_or("unavailable"),
            receipt["bytes"]
        ));
    }
    lines.extend(output.stages.iter().map(|stage| {
        format!(
            "{}: {} · finding observations: {}",
            stage["name"].as_str().unwrap_or("unnamed stage"),
            stage["status"].as_str().unwrap_or("unknown"),
            stage["findings"]
        )
    }));
    lines.join("\n")
}

fn stage_error_messages(stage: &StageOutcome) -> Vec<String> {
    let messages = stage
        .value
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .map(|message| format!("{}: {message}", stage.name))
        .collect::<Vec<_>>();
    if messages.is_empty() {
        vec![format!("{} did not produce results", stage.name)]
    } else {
        messages
    }
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
    run_id: &str,
    failed_stage: &str,
    prepare: StageOutcome,
    started: Instant,
) -> Value {
    let errors = prepare
        .value
        .get("errors")
        .cloned()
        .unwrap_or_else(|| json!([format!("{failed_stage} failed")]));
    let reason = errors
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_str)
        .unwrap_or("The stage did not complete; inspect the failure receipt");
    let _ = target;
    json!({
        "ok": false,
        "status": "failed",
        "summary": format!(
            "APK preparation stopped: {reason} ({}ms)",
            started.elapsed().as_millis()
        ),
        "output": format!("APK action stopped at {failed_stage}: {reason}\nInspect prior derived output and the failure receipt. Revise APK inputs before another attempt."),
        "data": {
            "runId": run_id,
            "runIds": [],
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
        "status":stage.value.get("status").cloned().unwrap_or_else(||json!(if stage_ok(stage){"completed"}else{"failed"})),
        "summary": stage.value.get("summary").cloned().unwrap_or(Value::Null),
        "findings": stage_findings.len(),
        "findingItems": stage_findings,
        "runIds": stage_run_ids(stage),
        "errors": stage.value.get("errors").cloned().unwrap_or(json!([])),
    })
}

fn pipeline_run_ids(stages: &[StageOutcome]) -> Vec<String> {
    let mut run_ids = std::collections::BTreeSet::new();
    for stage in stages {
        run_ids.extend(stage_run_ids(stage));
    }
    run_ids.into_iter().collect()
}

fn stage_run_ids(stage: &StageOutcome) -> Vec<String> {
    let mut run_ids = std::collections::BTreeSet::new();
    for pointer in ["/data/runId", "/data/persisted/runId", "/data/runIds"] {
        if let Some(value) = stage.value.pointer(pointer) {
            collect_run_id_values(value, &mut run_ids);
        }
    }
    run_ids.into_iter().collect()
}

fn collect_run_id_values(value: &Value, run_ids: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::String(run_id) if !run_id.trim().is_empty() => {
            run_ids.insert(run_id.trim().to_string());
        }
        Value::Array(values) => {
            for value in values {
                collect_run_id_values(value, run_ids);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_run_id_values(value, run_ids);
            }
        }
        _ => {}
    }
}

fn stage_findings_array(value: &Value) -> Vec<Value> {
    value
        .pointer("/data/findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
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
        StageOutcome {
            name,
            value: payload,
        }
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
    fn cancellation_after_one_stage_never_invokes_the_next() {
        let config = crate::V2Config::default();
        let cancel = crate::scan::ScanCancellation::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: Some(&cancel),
            authorization: Default::default(),
        };
        let mut stages = Vec::new();
        push_stage(&mut stages, "first", &ctx, || {
            cancel.cancel();
            Ok(json!({"ok":true}))
        });
        let invoked = std::cell::Cell::new(false);
        push_stage(&mut stages, "second", &ctx, || {
            invoked.set(true);
            Ok(json!({"ok":true}))
        });
        assert!(!invoked.get());
        assert!(stage_ok(&stages[0]));
        assert!(!stage_ok(&stages[1]));
    }

    #[test]
    fn prepared_limits_and_binaries_reach_their_own_stages() {
        let value = json!({"apk":"owned.apk","timeoutMs":50,"maxApkBytes":100,
            "unzipBin":"owned-unzip","jadxBin":"owned-jadx","apktoolBin":"owned-apktool",
            "semgrepBin":"owned-semgrep","includeLibraries":true});
        let plan = ScanPlan::from_input(&value, Path::new("/tmp/owned"), "owned".into()).unwrap();
        for key in [
            "timeoutMs",
            "maxApkBytes",
            "unzipBin",
            "jadxBin",
            "apktoolBin",
        ] {
            assert_eq!(plan.apk_input[key], value[key]);
        }
        assert_eq!(plan.workspace_input["binary"], value["semgrepBin"]);
        assert_eq!(plan.workspace_input["includeLibraries"], true);
        assert_eq!(plan.workspace_input["timeoutMs"], 50);
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
    fn failed_child_stage_makes_pipeline_partial_not_completed() {
        let plan = ScanPlan::from_input(
            &json!({"apk": "./app.apk", "skipNative": true}),
            Path::new("/tmp/ws"),
            "scan-apk".to_string(),
        )
        .unwrap();
        let output = scan_pipeline_output(
            &plan,
            stage("prepare", true, 0),
            vec![
                stage("manifest-scan", true, 2),
                stage("code-scan", false, 0),
            ],
            Instant::now(),
        );

        assert_eq!(output["ok"], true);
        assert_eq!(output["status"], "partial");
        assert_eq!(output["data"]["totals"]["failed"], 1);
        assert_eq!(output["data"]["totals"]["skipped"], 1);
        assert!(output["errors"][0]
            .as_str()
            .unwrap()
            .contains("code-scan: boom"));
        assert_eq!(
            crate::module_result::tool_result_status(&output),
            crate::module_result::ToolResultStatus::Partial
        );
    }

    #[test]
    fn intentional_skips_do_not_count_as_failures() {
        let plan = ScanPlan::from_input(
            &json!({
                "apk": "./app.apk",
                "skipNative": true,
                "skipCode": true,
                "skipHybrid": true,
            }),
            Path::new("/tmp/ws"),
            "scan-apk".to_string(),
        )
        .unwrap();
        let output = scan_pipeline_output(
            &plan,
            stage("prepare", true, 0),
            vec![stage("manifest-scan", true, 1)],
            Instant::now(),
        );

        assert_eq!(output["status"], "partial");
        assert_eq!(output["data"]["totals"]["failed"], 0);
        assert_eq!(output["data"]["totals"]["skipped"], 3);
        assert!(output["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn plan_rejects_missing_apk() {
        let target = std::path::PathBuf::from("/tmp/ws");
        let error = ScanPlan::from_input(&json!({}), &target, "scan-apk".to_string())
            .expect_err("missing apk rejected");
        assert!(error.to_string().contains("requires 'apk'"));
    }

    #[test]
    fn plan_accepts_apk_path_alias_and_skip_flags() {
        let target = std::path::PathBuf::from("/tmp/ws");
        let input = json!({
            "apkPath": "./app.apk",
            "decompiler": "jadx",
            "skipNative": true,
            "skipCode": true,
        });
        let plan = ScanPlan::from_input(&input, &target, "scan-apk".to_string()).unwrap();
        assert_eq!(
            plan.apk_input.get("apk"),
            Some(&Value::String("./app.apk".into()))
        );
        assert_eq!(
            plan.apk_input.get("decompiler"),
            Some(&Value::String("jadx".into()))
        );
        assert!(plan.skip_native);
        assert!(plan.skip_code);
        assert!(!plan.skip_hybrid);
    }

    #[test]
    fn plan_skip_webview_alias_still_works() {
        let target = std::path::PathBuf::from("/tmp/ws");
        let input = json!({"apk": "./app.apk", "skipWebview": true});
        let plan = ScanPlan::from_input(&input, &target, "scan-apk".to_string()).unwrap();
        assert!(plan.skip_code);
    }
}
