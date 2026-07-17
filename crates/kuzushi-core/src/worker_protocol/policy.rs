use super::*;

#[derive(Clone, Copy)]
pub(super) enum FsPolicyAction {
    Read,
    Write,
    Remove,
}

pub(super) fn authorize_fs_grant<'a>(
    grants: &'a Grant,
    scope: FsScope,
    action: FsPolicyAction,
) -> Result<&'a FsScopeGrant, KwpError> {
    let grant = grants
        .fs_scope(scope)
        .ok_or_else(|| KwpError::denied(missing_fs_capability(action)))?;
    if requires_fs_write(action) && (scope == FsScope::Input || grant.mode != FsMode::Rw) {
        return Err(KwpError::denied(missing_fs_capability(action)));
    }
    Ok(grant)
}

pub(super) fn validate_fs_path(scope: FsScope, path: &str) -> Result<(), KwpError> {
    validate_broker_fs_path(scope, path)
}

pub(super) fn authorize_runtime_grant(grants: &Grant) -> Result<&RuntimeGrant, KwpError> {
    grants
        .runtime
        .as_ref()
        .ok_or_else(|| KwpError::denied("runtime"))
}

pub(super) fn authorize_artifact_grant(grants: &Grant) -> Result<&ArtifactsGrant, KwpError> {
    grants
        .artifacts
        .as_ref()
        .filter(|grant| grant.write)
        .ok_or_else(|| KwpError::denied("artifacts.write"))
}

pub(super) fn authorize_findings_grant(
    grants: &Grant,
    finding_count: usize,
) -> Result<&FindingsGrant, KwpError> {
    let grant = grants
        .findings
        .as_ref()
        .filter(|grant| grant.create)
        .ok_or_else(|| KwpError::denied("findings.create"))?;
    if grant
        .max_per_invocation
        .is_some_and(|maximum| finding_count > maximum as usize)
    {
        return Err(KwpError::quota("findings.count"));
    }
    Ok(grant)
}

pub(super) fn authorize_bus_topic(grants: &Grant, topic: &str) -> Result<(), KwpError> {
    if grants
        .bus
        .produce
        .iter()
        .any(|pattern| pattern.matches(topic))
    {
        Ok(())
    } else {
        Err(KwpError::denied("bus.produce"))
    }
}

pub(super) fn validate_bus_topic(topic: &str) -> Result<(), KwpError> {
    if topic.trim().is_empty() {
        Err(KwpError::BadRequest("bus topic omitted".to_string()))
    } else {
        Ok(())
    }
}

pub(super) fn authorize_mcp_grant<'a>(
    grants: &'a Grant,
    catalog: &McpCatalog,
    expected_invocation: &InvocationId,
    request: &mut McpCallRequest,
) -> Result<&'a McpGrant, KwpError> {
    ensure_invocation_matches(expected_invocation, &request.invocation_id)?;
    let grant = grants
        .mcp_grant(&request.alias)
        .ok_or_else(|| KwpError::denied("mcp"))?;
    validate_mcp_request(grant, request, catalog)?;
    apply_mcp_grant_limits(grant, &mut request.limits);
    Ok(grant)
}

pub(super) fn authorize_fuzz_grant<'a>(
    grants: &'a Grant,
    expected_invocation: &InvocationId,
    request: &FuzzRunRequest,
) -> Result<&'a FuzzGrant, KwpError> {
    ensure_invocation_matches(expected_invocation, &request.invocation_id)?;
    let grant = grants
        .fuzz
        .as_ref()
        .ok_or_else(|| KwpError::denied("fuzz"))?;
    validate_authorized_fuzz_request(grants, grant, request)?;
    Ok(grant)
}

pub(super) fn reserve_mcp_call(
    calls: &mut BTreeMap<String, u32>,
    grant: &McpGrant,
    request: &McpCallRequest,
) -> Result<(), KwpError> {
    let used = calls.entry(request.alias.clone()).or_default();
    *used = used.saturating_add(1);
    check_count(*used, grant.max_calls_per_invocation, "mcp.calls")?;
    check_u64(
        request.limits.cpu_seconds,
        grant.max_cpu_seconds_per_invocation,
        "mcp.cpu_seconds",
    )?;
    check_u64(
        request.limits.artifact_bytes,
        grant.max_artifacts_bytes_per_invocation,
        "mcp.artifact_bytes",
    )
}

pub(super) fn reserve_mcp_result(
    bytes_by_alias: &mut BTreeMap<String, u64>,
    grant: &McpGrant,
    result: &McpCallResult,
) -> Result<(), KwpError> {
    let bytes = serde_json::to_vec(result)
        .map_err(|error| KwpError::Internal(error.to_string()))?
        .len() as u64;
    let used = bytes_by_alias.entry(grant.alias.clone()).or_default();
    *used = used
        .checked_add(bytes)
        .ok_or_else(|| KwpError::quota("mcp.bytes"))?;
    check_u64(Some(*used), grant.max_bytes_per_invocation, "mcp.bytes")
}

pub(super) fn reserve_fuzz_job(
    jobs: &mut u32,
    grant: &FuzzGrant,
    request: &FuzzRunRequest,
) -> Result<(), KwpError> {
    *jobs = jobs.saturating_add(1);
    check_count(*jobs, grant.max_jobs_per_invocation, "fuzz.jobs")?;
    check_u64(
        request.limits.cpu_seconds,
        grant.max_cpu_seconds_per_invocation,
        "fuzz.cpu_seconds",
    )?;
    check_u64(
        request.limits.artifact_bytes,
        grant.max_artifacts_bytes_per_invocation,
        "fuzz.artifact_bytes",
    )
}

pub(super) fn audit_decision<T>(result: &Result<T, KwpError>) -> (AuditDecision, Value) {
    match result {
        Ok(_) => (AuditDecision::Allow, Value::Null),
        Err(error) => (
            AuditDecision::Deny,
            serde_json::json!({ "errorCode": error.code(), "error": error.to_string() }),
        ),
    }
}

fn missing_fs_capability(action: FsPolicyAction) -> &'static str {
    match action {
        FsPolicyAction::Read => "fs",
        FsPolicyAction::Write => "fs.write",
        FsPolicyAction::Remove => "fs.remove",
    }
}

fn requires_fs_write(action: FsPolicyAction) -> bool {
    matches!(action, FsPolicyAction::Write | FsPolicyAction::Remove)
}

fn ensure_invocation_matches(
    expected: &InvocationId,
    actual: &InvocationId,
) -> Result<(), KwpError> {
    if expected == actual {
        Ok(())
    } else {
        Err(KwpError::NoActiveInvocation)
    }
}

#[cfg(test)]
mod tests;
