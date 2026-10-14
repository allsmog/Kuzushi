use super::*;
use crate::runtime::{AgentReadScope, AgentToolPolicyAuthorization};
use crate::workspace::{
    resolve_accepted_scan_scope_selection, AcceptedScanScopeSelection, ScanScopeRef,
};

#[cfg(test)]
mod tests;

pub(crate) fn selected_agentic_scope(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> Result<Option<AcceptedScanScopeSelection>> {
    let Some(value) = input.get("scanScopeRef") else {
        return Ok(None);
    };
    validate_agentic_scope_options(input)?;
    require_scoped_repository(target, ctx)?;
    let reference: ScanScopeRef = serde_json::from_value(value.clone())
        .context("scanScopeRef must identify an exact accepted scope")?;
    resolve_accepted_scan_scope_selection(ctx, &reference).map(Some)
}

fn require_scoped_repository(target: &Path, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    let workspace = ctx
        .workspace
        .context("accepted discovery scope requires an active repository")?;
    anyhow::ensure!(std::fs::canonicalize(target)? == std::fs::canonicalize(workspace.root())?, "accepted discovery scope belongs to the active repository; target override cannot rebind its files");
    Ok(())
}

pub(crate) fn validate_agentic_scope_options(input: &Value) -> Result<()> {
    anyhow::ensure!(input.get("strategy").and_then(Value::as_str).unwrap_or("standard") == "standard", "accepted file membership requires the standard agentic strategy; chunked scoped discovery is unsupported");
    anyhow::ensure!(input.get("mcps") != Some(&Value::Bool(true)), "accepted file membership supports read-only file tools; MCP discovery requires a separately approved job");
    for key in [
        "includePatterns",
        "include_patterns",
        "excludePatterns",
        "exclude_patterns",
    ] {
        anyhow::ensure!(
            scope_pattern_is_empty(input.get(key)),
            "{key} cannot alter immutable accepted scope membership"
        );
    }
    Ok(())
}

fn scope_pattern_is_empty(value: Option<&Value>) -> bool {
    match value {
        None => true,
        Some(Value::Array(patterns)) => patterns.is_empty(),
        _ => false,
    }
}

pub(crate) fn scoped_agent_policy(
    target: &Path,
    scope: &AcceptedScanScopeSelection,
) -> Result<AgentToolPolicy> {
    let membership = AgentReadScope::new(
        scope
            .discovery_files
            .iter()
            .chain(&scope.context_files)
            .cloned(),
    )?;
    Ok(AgentToolPolicyAuthorization::read_only_scope(target, membership)?.policy)
}

pub(crate) fn acknowledge_scoped_agent_policy(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
) -> Result<()> {
    let Some(authorization) = AgentToolPolicyAuthorization::for_scoped_policy(&run.tool_policy)?
    else {
        return Ok(());
    };
    let receipt = runtime.authorize_tool_policy_blocking(&authorization)
        .context("selected runtime cannot acknowledge exact read membership; no scoped model request started")?;
    receipt.validate_for(&authorization)
}

pub(crate) fn scoped_seed_files(scope: &AcceptedScanScopeSelection) -> Vec<String> {
    let mut files = Vec::new();
    let length = scope.discovery_files.len().max(scope.context_files.len());
    for index in 0..length {
        files.extend(scope.discovery_files.get(index).cloned());
        files.extend(scope.context_files.get(index).cloned());
    }
    let mut seen = std::collections::BTreeSet::new();
    files.retain(|file| seen.insert(file.clone()));
    files
}

pub(crate) fn prepare_agentic_inventory(
    target: &Path,
    scope: Option<&AcceptedScanScopeSelection>,
    options: &AgenticSastInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<AgenticInventory> {
    let probe = || ctx.ensure_active();
    let mut progress = |entries| emit_inventory_preparation(ctx, entries);
    match scope {
        Some(scope) => collect_literal_inventory(
            target,
            options,
            &scoped_seed_files(scope),
            &probe,
            &mut progress,
        ),
        None => collect_bounded_inventory(
            target,
            options,
            MAX_AGENTIC_INVENTORY_ENTRIES,
            &probe,
            &mut progress,
        ),
    }
}

pub(crate) fn scope_receipt(run: &AgenticSastRun) -> Option<AgenticScopeReceipt> {
    let scope = run.scope.as_ref()?;
    let read_scope = run.tool_policy.read_scope.as_ref()?;
    Some(AgenticScopeReceipt {
        reference: scope.reference.clone(),
        name: scope.name.clone(),
        discovery_files: scope.discovery_files.len(),
        inherited_context_files: scope.context_files.len(),
        read_membership_sha256: read_scope.sha256.clone(),
    })
}

pub(crate) fn scoped_prompt_lines(scope: &AcceptedScanScopeSelection) -> Vec<String> {
    let context = scope
        .context_files
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    vec![format!("Accepted discovery scope: {} · {} discovery files · {} inherited context-only files", scope.name, scope.discovery_files.len(), scope.context_files.len()),
        "Read, list and search tools enforce the accepted membership. Findings must be anchored in discovery files. Inherited dependencies provide context; they are not additional discovery work.".into(),
        format!("Context-only path preview (at most 20): {context}. Additional members remain accessible through the constrained file tools.")]
}

pub(crate) fn retain_discovery_findings(
    scope: Option<&AcceptedScanScopeSelection>,
    findings: &mut Vec<Finding>,
) -> Vec<Finding> {
    let Some(scope) = scope else {
        return Vec::new();
    };
    let allowed = scope
        .discovery_files
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut held = Vec::new();
    findings.retain(|finding| {
        if allowed.contains(&finding.file_path) {
            return true;
        }
        held.push(finding.clone());
        false
    });
    held
}
