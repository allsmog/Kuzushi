use super::prelude::*;
use super::*;

pub(crate) fn query_systems_invariants(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    _options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
) -> Result<SystemsInvariantOutput> {
    // Pick a sub-agent role appropriate for the dominant surface kind.
    // When at least one Rust unsafe-region surface is present, the
    // UnsafeBlockReasoner preamble keeps the agent on-task. Otherwise
    // fall through to Generic — same behavior as before.
    let role = pick_role_for_invariants(context);
    let request = AgentQueryRequest::new(
        model.to_string(),
        target.to_path_buf(),
        SYSTEMS_INVARIANT_SYSTEM_PROMPT.to_string(),
        format!(
            "Extract safety invariants for these low-level surfaces. Return JSON with invariants[].\n\n{}",
            serde_json::to_string_pretty(context)?
        ),
    )
    .with_tool_policy(agent_tool_policy);
    let request =
        request.with_structured_output(crate::runtime::AgentStructuredOutput::json_schema(
            "SystemsInvariants",
            invariants_schema(),
        ));
    let response = if role == SubagentRole::Generic {
        runtime.query_blocking(request.clone())?
    } else {
        runtime.spawn_subagent_blocking(role, request.clone())?
    };
    let raw = parse_or_repair_required_structured_json(
        response,
        StructuredJsonContract::new(
            "systems-hunt:systems-invariant-extract",
            "SystemsInvariants",
            invariants_schema(),
        ),
        require_json_object,
        |repair_prompt, output| {
            let repair_request = AgentQueryRequest::new(
                request.model.clone(),
                request.cwd.clone(),
                request.system_prompt.clone(),
                repair_prompt,
            )
            .with_tool_policy(request.tool_policy.clone())
            .with_structured_output(output);
            if role == SubagentRole::Generic {
                runtime.query_blocking(repair_request)
            } else {
                runtime.spawn_subagent_blocking(role, repair_request)
            }
        },
    )?;
    Ok(SystemsInvariantOutput {
        invariants: parse_invariants(&raw),
    })
}

pub(crate) fn pick_role_for_invariants(context: &SystemsContextOutput) -> SubagentRole {
    let has_rust_unsafe = context
        .surfaces
        .iter()
        .any(|s| s.kind == "unsafe-region" && s.file_path.to_ascii_lowercase().ends_with(".rs"));
    if has_rust_unsafe {
        return SubagentRole::UnsafeBlockReasoner;
    }
    let has_ffi = context
        .surfaces
        .iter()
        .any(|s| s.kind == "ffi-boundary" || s.domains.iter().any(|d| d == "ffi"));
    if has_ffi {
        return SubagentRole::FfiBoundaryReasoner;
    }
    let has_rust_provenance = context.surfaces.iter().any(|s| {
        s.kind == "resource-provenance" && s.file_path.to_ascii_lowercase().ends_with(".rs")
    });
    if has_rust_provenance {
        return SubagentRole::LifetimeAliasingReasoner;
    }
    SubagentRole::Generic
}

pub async fn try_augment_with_index(
    surfaces: Vec<RankedSystemsSurface>,
) -> Vec<RankedSystemsSurface> {
    score_with_index(surfaces).await
}

pub(crate) async fn score_with_index(
    surfaces: Vec<RankedSystemsSurface>,
) -> Vec<RankedSystemsSurface> {
    use kuzushi_codeindex::IndexFacade;

    let mut facade = IndexFacade::with_available_backends().await;
    if !codeindex_has_joern_backend(&facade) {
        return surfaces;
    }

    let ffi_set = indexed_ffi_files(&mut facade).await;

    let mut out = Vec::with_capacity(surfaces.len());
    for surface in surfaces {
        out.push(index_score_surface(&mut facade, &ffi_set, surface).await);
    }
    out
}
