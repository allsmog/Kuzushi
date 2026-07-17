use super::*;

pub(in crate::modules) fn run_android_apk_check_env(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    emit_trace_step(ctx, "tool", "check", "android-apk:check-env start");
    let tools = AndroidApkToolchain::from_tool_input(&input);
    let report = ToolchainReport::probe(&tools);
    emit_trace_step(
        ctx,
        "done",
        "check",
        &format!(
            "android-apk:check-env complete · missing={}",
            report.missing_count()
        ),
    );
    Ok(report.to_tool_json())
}

pub(in crate::modules) fn run_android_apk_prepare(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    emit_trace_step(
        ctx,
        "tool",
        "prepare",
        &format!("android-apk:prepare start · workspace={}", target.display()),
    );
    let outcome = match ctx.with_cancellation(|cancel| prepare_apk(&input, &target, cancel)) {
        Ok(outcome) => outcome,
        Err(error) => return Ok(failed_tool_output("android-apk:prepare", &target, error)),
    };
    emit_trace_step(ctx, "done", "prepare", "android-apk:prepare complete");
    Ok(outcome.to_tool_json())
}

fn emit_trace_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, message: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, message.to_string()).emit();
    }
}
