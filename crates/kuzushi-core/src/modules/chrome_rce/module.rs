use super::*;

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
    match name {
        "chrome-rce:scan" => scan(input, ctx),
        "chrome-rce:review-trigger" => review_trigger(input, ctx),
        _ => anyhow::bail!("unknown chrome-rce tool {name:?}"),
    }
}

pub(in crate::modules) fn scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "chrome-rce:scan target is not a directory: {}",
            target.display()
        );
    }
    let mut findings = Vec::new();
    collect_findings(&target, &target, &mut findings)?;
    let persisted = persist_tool_findings("chrome-rce", &target, &findings, ctx)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "chrome-rce:scan found {} finding{} under {}",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            target.display()
        ),
        "data": {
            "target": target.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
    }))
}
