use super::*;

pub(super) fn descriptor() -> ToolDescriptor {
    tool_with_options("pack:scopes",
        "Build bounded inventory and review source-bound scan scope drafts. Edits preserve immutable revisions. Acceptance approves boundaries only, never scans or spending. No model calls.",
        vec![
            opt("operation", OptionType::Enum, "Scope action.")
                .choices(&["create", "latest", "read", "edit", "accept", "files"]).default(json!("create")),
            opt("draft", OptionType::Json, "Scope draft for create. Omit to keep the whole repository together."),
            opt("proposalRef", OptionType::Json, "Exact saved scope revision. Required for read, edit, accept, and files."),
            opt("edit", OptionType::Json, "One explicit rename, merge, split, exclusion, boundary edit, shared-discovery choice, or whole-repository edit."),
            opt("acknowledgements", OptionType::Json, "Acceptance acknowledgements for inventory limitations, overlapping discovery, and exclusions. Required for accept."),
            opt("fileFilter", OptionType::Json, "Membership, uncovered, excluded, overlap, or conflicting-exclusion file filter. Required for files."),
            opt("offset", OptionType::Int, "File page offset.").integer_range(0, 100000).default(json!(0)),
            opt("pageSize", OptionType::Int, "File page size, at most 128.").integer_range(1, 128).default(json!(32)),
        ]).without_phase_result()
}

pub(in crate::modules) fn execute(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let operation = input["operation"]
        .as_str()
        .context("scope operation is required")?;
    validate_action_options(input, operation)?;
    if operation == "latest" {
        return latest_review(ctx);
    }
    if operation == "files" {
        return file_page(input, ctx);
    }
    let review = if operation == "create" {
        let draft = input
            .get("draft")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        crate::workspace::create_scan_scope_proposal(ctx, draft)?
    } else {
        execute_review(input, ctx, operation)?
    };
    Ok(
        json!({"ok":true, "status":"completed", "summary":format!("Scope revision {} saved or read. {} inventoried files; {} uncovered; {} overlap; {} without content identity. Scope acceptance does not approve scans or spending.",
        review.reference.revision, review.coverage.enumerated_files, review.coverage.uncovered_files.total, review.coverage.overlaps.total, review.identity_omissions.total),
        "data":review}),
    )
}

fn latest_review(ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let review = crate::workspace::load_latest_scan_scope_proposal(ctx)?;
    let summary = if review.is_some() {
        "Latest saved scope revision read. No jobs started."
    } else {
        "No saved scope draft. Build inventory when ready."
    };
    Ok(json!({"ok":true, "status":"completed", "summary":summary, "data":{"review":review}}))
}

fn execute_review(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    operation: &str,
) -> Result<crate::workspace::ScanScopeReview> {
    use crate::workspace::*;
    let reference = required_json(input, "proposalRef")?;
    match operation {
        "read" => load_scan_scope_proposal_cancellable(
            ctx.workspace
                .context("scope review requires an active target")?,
            &reference,
            &|| ctx.is_cancelled(),
        ),
        "edit" => edit_scan_scope_proposal(ctx, &reference, required_json(input, "edit")?),
        "accept" => {
            accept_scan_scope_proposal(ctx, &reference, required_json(input, "acknowledgements")?)
        }
        _ => anyhow::bail!("unsupported scope operation"),
    }
}

fn file_page(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("scope file review requires an active target")?;
    let page = crate::workspace::scan_scope_proposal_files_cancellable(
        workspace,
        &required_json(input, "proposalRef")?,
        required_json(input, "fileFilter")?,
        input["offset"]
            .as_u64()
            .context("file offset is required")? as usize,
        input["pageSize"]
            .as_u64()
            .context("file page size is required")? as usize,
        &|| ctx.is_cancelled(),
    )?;
    Ok(
        json!({"ok":true, "status":"completed", "summary":format!("{} of {} files, offset {}",page.files.len(),page.total,page.offset), "data":page}),
    )
}

fn required_json<T: serde::de::DeserializeOwned>(input: &Value, key: &str) -> Result<T> {
    serde_json::from_value(
        input
            .get(key)
            .with_context(|| format!("scope {key} is required"))?
            .clone(),
    )
    .with_context(|| format!("scope {key} is malformed"))
}

fn validate_action_options(input: &Value, operation: &str) -> Result<()> {
    for (key, owner) in [
        ("draft", "create"),
        ("edit", "edit"),
        ("acknowledgements", "accept"),
        ("fileFilter", "files"),
    ] {
        anyhow::ensure!(
            input.get(key).is_none() || operation == owner,
            "scope {key} is only valid for {owner}"
        );
    }
    anyhow::ensure!(
        !matches!(operation, "create" | "latest") || input.get("proposalRef").is_none(),
        "create/latest does not accept a saved revision"
    );
    Ok(())
}
