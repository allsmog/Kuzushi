use super::*;
use crate::capabilities::chrome_rce::{run_review_trigger, run_scan, ChangedPathLimits};
use crate::findings::ToolFindingsSink;

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "chrome-rce",
        "Chrome RCE",
        ModuleKind::Defense,
        "Source review signals for Chromium handle checks and changed hot paths.",
        chrome_tools(),
        vec![
            dag("chrome-rce:scan", "findings", &["context:build"]),
            dag("chrome-rce:review-trigger", "review", &[]),
        ],
    )
}

fn chrome_tools() -> Vec<ToolDescriptor> {
    vec![chrome_scan_tool(), changed_path_review_tool()]
}

fn chrome_scan_tool() -> ToolDescriptor {
    tool_with_options("chrome-rce:scan",
        "Inspect Chromium source for the bundled handle-check heuristic. Results are review signals. A reached finding limit leaves partial work.",
        vec![target_option(), max_findings_option(50).integer_range(1, i64::MAX)])
        .with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required))
        .with_discovery_maturity(ModuleMaturity::Labs)
}

fn changed_path_review_tool() -> ToolDescriptor {
    tool_with_options("chrome-rce:review-trigger",
        "Inspect bounded committed path changes against a recorded Git merge base. Auxiliary Labs Map review hints; no vulnerability findings, source execution or phase completion. Working-tree, staged and untracked changes are excluded.",
        vec![target_option(),
            opt("diffBase", OptionType::String, "Git base reference. The recorded merge base is compared with the recorded HEAD commit.").aliases(&["diff_base"]),
            opt("maxChangedFiles", OptionType::Int, "Maximum changed paths retained for review-pattern matching. Omitted paths make the result partial.")
                .aliases(&["max_changed_files"]).default(json!(1000)).integer_range(1, 100_000),
            opt("maxGitOutputBytes", OptionType::Int, "Maximum Git diff path-output bytes. Excess output fails the comparison without publishing hints.")
                .aliases(&["max_git_output_bytes"]).default(json!(1024 * 1024)).integer_range(256, 8 * 1024 * 1024),
            opt("gitTimeoutMs", OptionType::Int, "Shared deadline in milliseconds for the complete Git comparison.")
                .aliases(&["git_timeout_ms", "timeoutMs"]).default(json!(30_000)).integer_range(1, 120_000),
        ])
        .with_policy(tool_policy(ToolPhase::Map, RuntimeRequirement::Never, ToolEffect::Read,
            WorkspaceRequirement::Required, FindingStoreRequirement::Optional))
        .with_discovery_maturity(ModuleMaturity::Labs)
        .without_phase_result()
}

pub(in crate::modules) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let handler = chrome_rce_handler(name)?;
    handler(input, ctx)
}

type ChromeRceHandler = fn(Value, &ToolExecutionContext<'_>) -> Result<Value>;

fn chrome_rce_handler(name: &str) -> Result<ChromeRceHandler> {
    CHROME_RCE_HANDLERS
        .iter()
        .find_map(|(tool_name, handler)| (*tool_name == name).then_some(*handler))
        .ok_or_else(|| anyhow::anyhow!("unknown chrome-rce tool {name:?}"))
}

const CHROME_RCE_HANDLERS: &[(&str, ChromeRceHandler)] = &[
    ("chrome-rce:scan", scan),
    ("chrome-rce:review-trigger", review_trigger),
];

pub(in crate::modules) fn scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let max_findings = scan_max_findings(&input)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "scan",
                format!("chrome-rce:scan start · target={}", target.display()),
            )
            .emit();
    }
    let result = run_scan(&target, ToolFindingsSink::for_context(ctx), max_findings);
    if let (Some(trace), Ok(output)) = (ctx.trace, &result) {
        let count = output
            .pointer("/data/count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let _ = trace
            .step(
                "done",
                "scan",
                format!(
                    "chrome-rce:scan {} · {count} findings",
                    output["status"].as_str().unwrap_or("outcome unavailable")
                ),
            )
            .emit();
    }
    result
}

fn scan_max_findings(input: &Value) -> Result<usize> {
    let value = input
        .get("maxFindings")
        .and_then(Value::as_u64)
        .context("chrome-rce:scan requires a positive prepared maxFindings")?;
    usize::try_from(value).context("chrome-rce:scan maxFindings exceeds platform capacity")
}

pub(in crate::modules) fn review_trigger(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let diff_base = string_input_any(&input, &["diffBase", "diff_base"]);
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("tool", "review-trigger", "chrome-rce:review-trigger start")
            .emit();
    }
    let result = run_review_trigger(
        &target,
        diff_base.as_deref(),
        review_limits(&input)?,
        ctx.cancellation,
    );
    if let (Some(trace), Ok(output)) = (ctx.trace, &result) {
        let count = output
            .pointer("/data/count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let _ = trace
            .step(
                "done",
                "review-trigger",
                format!("chrome-rce:review-trigger complete · {count} review hints"),
            )
            .emit();
    }
    result
}

fn review_limits(input: &Value) -> Result<ChangedPathLimits> {
    Ok(ChangedPathLimits {
        max_changed_files: prepared_size(input, "maxChangedFiles")?,
        max_git_output_bytes: prepared_size(input, "maxGitOutputBytes")?,
        git_timeout_ms: input["gitTimeoutMs"]
            .as_u64()
            .context("Expected prepared gitTimeoutMs")?,
    })
}

fn prepared_size(input: &Value, name: &str) -> Result<usize> {
    let value = input[name]
        .as_u64()
        .with_context(|| format!("Expected prepared {name}"))?;
    usize::try_from(value).with_context(|| format!("{name} exceeds platform capacity"))
}
