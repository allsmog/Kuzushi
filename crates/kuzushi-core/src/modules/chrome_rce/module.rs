use super::*;
use crate::capabilities::chrome_rce::{run_review_trigger, run_scan, ChromeRcePersistence};

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "chrome-rce",
        "Chrome RCE",
        ModuleKind::Defense,
        "Detection rules anchored to verified Chrome and Chromium RCE CVEs.",
        vec![
            tool_with_options(
                "chrome-rce:scan",
                "Scan for Chrome RCE bug patterns.",
                vec![target_option(), max_findings_option(50)],
            ),
            tool_with_options(
                "chrome-rce:review-trigger",
                "Review candidate Chrome RCE trigger paths.",
                vec![
                    target_option(),
                    opt(
                        "diffBase",
                        OptionType::String,
                        "Git reference for PR hot-path review.",
                    )
                    .aliases(&["diff_base"]),
                ],
            ),
        ],
        vec![
            dag("chrome-rce:scan", "findings", &["context:build"]),
            dag("chrome-rce:review-trigger", "review", &["chrome-rce:scan"]),
        ],
    )
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
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "scan",
                format!("chrome-rce:scan start · target={}", target.display()),
            )
            .emit();
    }
    let result = run_scan(&target, chrome_rce_persistence(ctx));
    if let (Some(trace), Ok(output)) = (ctx.trace, &result) {
        let count = output
            .pointer("/data/count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let _ = trace
            .step(
                "done",
                "scan",
                format!("chrome-rce:scan complete · {count} findings"),
            )
            .emit();
    }
    result
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
    let result = run_review_trigger(&target, diff_base.as_deref(), chrome_rce_persistence(ctx));
    if let (Some(trace), Ok(output)) = (ctx.trace, &result) {
        let count = output
            .pointer("/data/count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let _ = trace
            .step(
                "done",
                "review-trigger",
                format!("chrome-rce:review-trigger complete · {count} hot paths"),
            )
            .emit();
    }
    result
}

fn chrome_rce_persistence<'ctx>(ctx: &ToolExecutionContext<'ctx>) -> ChromeRcePersistence<'ctx> {
    ChromeRcePersistence {
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
    }
}
