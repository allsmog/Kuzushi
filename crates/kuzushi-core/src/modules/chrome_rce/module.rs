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
                    ),
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
    run_scan(&target, chrome_rce_persistence(ctx))
}

pub(in crate::modules) fn review_trigger(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let diff_base = string_input_any(&input, &["diffBase", "diff_base"]);
    run_review_trigger(&target, diff_base.as_deref(), chrome_rce_persistence(ctx))
}

fn chrome_rce_persistence<'ctx>(ctx: &ToolExecutionContext<'ctx>) -> ChromeRcePersistence<'ctx> {
    ChromeRcePersistence {
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
    }
}
