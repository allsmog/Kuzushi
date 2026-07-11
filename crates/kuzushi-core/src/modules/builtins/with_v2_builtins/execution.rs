use super::output_contract::normalize_tool_output_contract;
use super::*;
use crate::module_result::tool_result_status;

/// Opaque proof that canonical option, prompt, and workspace validation ran
/// for one specific operation and registry snapshot.
#[derive(Debug, Clone)]
pub struct PreparedToolInput {
    tool_name: String,
    value: Value,
    binding: PreparedDispatchBinding,
    authorization: ExecutionAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedDispatchBinding {
    registry_identity: u64,
    registry_fingerprint: [u8; 32],
    descriptor_fingerprint: [u8; 32],
    operation_fingerprint: [u8; 32],
}

impl PreparedToolInput {
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Bind the explicit `kuzushi run <tool>` authorization to this prepared
    /// operation only.
    pub fn authorize_explicit_headless(self) -> Self {
        self.authorize(
            crate::modules::execution_context::AuthorizationKind::ExplicitHeadless,
            &[],
        )
    }

    /// Bind a headless invocation and explicitly scope the named nested tools
    /// that the prepared operation may dispatch.
    pub fn authorize_explicit_headless_with_delegated_tools(
        self,
        delegated_tools: &[&str],
    ) -> Self {
        self.authorize(
            crate::modules::execution_context::AuthorizationKind::ExplicitHeadless,
            delegated_tools,
        )
    }

    /// Bind an interactive confirmation request to this prepared operation.
    pub fn authorize_requested(self, request: ExecutionAuthorization) -> Result<Self> {
        let mut prepared = self;
        prepared.authorization = request.bind_request(prepared.binding.operation_fingerprint)?;
        Ok(prepared)
    }

    pub fn authorize_requested_with_delegated_tools(
        self,
        request: ExecutionAuthorization,
        delegated_tools: &[&str],
    ) -> Result<Self> {
        let mut prepared = self;
        prepared.authorization = request.bind_request_with_delegated_tools(
            prepared.binding.operation_fingerprint,
            delegated_tools.iter().map(|tool| (*tool).to_string()),
        )?;
        Ok(prepared)
    }

    /// Bind an interactive confirmation and explicitly scope the named nested
    /// tools that the operation may dispatch.
    pub fn authorize_interactive_with_delegated_tools(
        self,
        delegated_tools: &[&str],
    ) -> Self {
        self.authorize(
            crate::modules::execution_context::AuthorizationKind::Interactive,
            delegated_tools,
        )
    }

    pub(in crate::modules) fn authorize_delegated(
        mut self,
        parent: &ExecutionAuthorization,
    ) -> Self {
        if let Some(grant) = parent.delegated_grant(
            &self.tool_name,
            self.binding.operation_fingerprint,
        ) {
            self.authorization = grant;
        }
        self
    }

    fn authorize(
        mut self,
        kind: crate::modules::execution_context::AuthorizationKind,
        delegated_tools: &[&str],
    ) -> Self {
        self.authorization = ExecutionAuthorization::bind(
            kind,
            self.binding.operation_fingerprint,
            delegated_tools.iter().map(|tool| (*tool).to_string()),
        );
        self
    }
}

impl ModuleRegistry {
    pub fn execute_tool(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Value> {
        self.execute_tool_with_runtime(name, input, ctx, None)
    }

    pub fn execute_tool_with_runtime(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        self.execute_tool_with_runtime_and_options(name, input, ctx, runtime, None)
    }

    pub fn execute_tool_with_runtime_and_options(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<Value> {
        let input = self.prepare_dispatch_input(name, input, ctx, option_store)?;
        self.dispatch_prepared_input_with_runtime(input, ctx, runtime)
    }

    pub fn prepare_tool_input_for_dispatch(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<Value> {
        let mut input = self.prepare_tool_input(name, input, option_store)?;
        normalize_workspace_path_options(self, name, &mut input, ctx, false, None)?;
        let input = input_with_declared_prompt_defaults(self, name, input, ctx)?;
        input_with_prompt_file_default(name, input, ctx)
    }

    pub fn prepare_dispatch_input(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<PreparedToolInput> {
        let value = self.prepare_tool_input_for_dispatch(name, input, ctx, option_store)?;
        let descriptor = self
            .resolve_tool(name)
            .with_context(|| format!("{name:?} has no dispatch descriptor"))?;
        Ok(PreparedToolInput {
            tool_name: name.to_string(),
            binding: self.prepared_dispatch_binding(name, &value, descriptor, ctx)?,
            value,
            authorization: ExecutionAuthorization::default(),
        })
    }

    pub fn prepare_tool_input(
        &self,
        name: &str,
        input: Value,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<Value> {
        let tool = self.resolve_tool(name);
        if tool.is_none() && !self.is_registered_dag_node(name) {
            anyhow::bail!(
                "unknown tool {name:?}. Next: run catalog:tools or use the Rust shell `tools` command"
            );
        }
        let input = prepare_input_with_stored_options(name, input, option_store, tool)?;
        Ok(if let Some(tool) = tool {
            validate_tool_input_options(tool, input)?
        } else {
            input
        })
    }

    pub fn dispatch_prepared_tool_with_runtime(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        // Public compatibility boundary: raw Value callers are revalidated.
        // New callers can carry the opaque proof and avoid this second pass.
        let prepared = self.prepare_dispatch_input(name, input, ctx, None)?;
        self.dispatch_prepared_input_with_runtime(prepared, ctx, runtime)
    }

    pub fn dispatch_prepared_input_with_runtime(
        &self,
        prepared: PreparedToolInput,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        let name = prepared.tool_name.as_str();
        let descriptor = self
            .resolve_tool(name)
            .with_context(|| format!("{name:?} has no dispatch descriptor"))?;
        self.verify_prepared_dispatch_binding(&prepared, descriptor, ctx)?;
        let authorization = prepared.authorization;
        let operation_binding = prepared.binding.operation_fingerprint;
        let mut input = prepared.value;
        let authorized_ctx = tool_context_with_authorization(ctx, authorization);
        authorized_ctx.ensure_active()?;
        enforce_descriptor_context(descriptor, &authorized_ctx, &operation_binding)?;
        normalize_workspace_path_options(
            self,
            name,
            &mut input,
            &authorized_ctx,
            true,
            Some(&operation_binding),
        )?;
        enforce_autonomy_posture(descriptor, authorized_ctx.config.autonomy)?;
        enforce_descriptor_approval(descriptor, &authorized_ctx, &operation_binding)?;
        self.enforce_runtime_requirement(name, &input, runtime)?;
        enforce_descriptor_finding_store(descriptor, &authorized_ctx)?;
        let result = self.invoke_prepared_executor(name, &input, &authorized_ctx, runtime);
        if result
            .as_ref()
            .is_ok_and(|output| tool_result_status(output).is_completed())
        {
            self.record_recent_tool_use(name, &authorized_ctx);
        }
        result
    }

    fn prepared_dispatch_binding(
        &self,
        name: &str,
        input: &Value,
        descriptor: &ToolDescriptor,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<PreparedDispatchBinding> {
        let registry_fingerprint = fingerprint_serializable(&self.tools)?;
        let descriptor_fingerprint = fingerprint_serializable(descriptor)?;
        let workspace = ctx
            .workspace
            .map(|workspace| workspace.root().to_string_lossy().into_owned());
        let operation_fingerprint = fingerprint_serializable(&(
            self.identity,
            registry_fingerprint,
            descriptor_fingerprint,
            name,
            input,
            workspace,
        ))?;
        Ok(PreparedDispatchBinding {
            registry_identity: self.identity,
            registry_fingerprint,
            descriptor_fingerprint,
            operation_fingerprint,
        })
    }

    fn verify_prepared_dispatch_binding(
        &self,
        prepared: &PreparedToolInput,
        descriptor: &ToolDescriptor,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<()> {
        let actual = self.prepared_dispatch_binding(
            &prepared.tool_name,
            &prepared.value,
            descriptor,
            ctx,
        )?;
        if actual != prepared.binding {
            anyhow::bail!(
                "prepared input for {:?} does not belong to this registry, descriptor, input, or workspace",
                prepared.tool_name
            )
        }
        Ok(())
    }

    fn invoke_prepared_executor(
        &self,
        name: &str,
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        let scoped_trace = scoped_tool_trace(ctx, name);
        let scoped_ctx;
        let ctx: &ToolExecutionContext<'_> = if let Some(handle) = scoped_trace.as_ref() {
            scoped_ctx = scoped_tool_context(ctx, handle);
            &scoped_ctx
        } else {
            ctx
        };
        let traced_runtime = traced_tool_runtime(runtime, scoped_trace.as_ref());
        let runtime = active_tool_runtime(runtime, traced_runtime.as_ref());

        let executor = self.executors.get(name).with_context(|| {
            format!("registered tool or DAG node {name:?} has no Rust executor mapping")
        })?;
        executor(self, name, input, ctx, runtime)
            .map(|output| normalize_tool_output_contract(name, output))
    }

    /// Record a recents entry at the shared dispatch boundary so scan, shell,
    /// and run all agree. Only called for `Ok` results (a failed run should not
    /// show up on the YOUR TOOLS shelf); only visible tools (matching the same
    /// hidden-tool/hidden-module policy as `tools_with_modules`) with a
    /// workspace are recorded. A shelf-write failure never fails the tool run,
    /// but it is reported on stderr so a corrupt shelf file is diagnosable
    /// instead of silently no-op'ing recents forever.
    fn record_recent_tool_use(&self, name: &str, ctx: &ToolExecutionContext<'_>) {
        let Some(workspace) = ctx.workspace else {
            return;
        };
        let is_visible_tool = self
            .resolve_tool(name)
            .is_some_and(|tool| self.is_tool_visible(tool));
        if !is_visible_tool {
            return;
        }
        let at = dispatch_timestamp();
        // Convenience state — a write failure must never fail the tool run,
        // but it must not be silent either: a corrupt tool-shelf.json should
        // be observable instead of making recents quietly no-op forever.
        if let Err(error) = crate::workspace::record_tool_use(workspace, name, &at) {
            eprintln!("kuzushi: failed to record recent tool use for {name:?}: {error:#}");
        }
    }

    fn enforce_runtime_requirement(
        &self,
        name: &str,
        input: &Value,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<()> {
        if runtime.is_some() || !self.tool_needs_runtime(name, input) {
            return Ok(());
        }
        if runtime_requirement_is_deferred_to_executor(name) {
            return Ok(());
        }
        anyhow::bail!(
            "{name} requires an agent runtime; configure a model/runtime before running it"
        )
    }
}

fn fingerprint_serializable(value: &impl serde::Serialize) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value).context("could not fingerprint dispatch contract")?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn tool_context_with_authorization<'a>(
    ctx: &ToolExecutionContext<'a>,
    authorization: ExecutionAuthorization,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config: ctx.config,
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
        trace: ctx.trace,
        cancellation: ctx.cancellation,
        authorization,
    }
}

/// Unix-seconds timestamp for a recents entry, as an opaque string. Read at the
/// dispatch edge (not in domain code), so the shelf domain stays clockless.
fn dispatch_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs().to_string())
        .unwrap_or_default()
}

/// Enforce the operator autonomy posture at the one shared dispatch boundary.
///
/// This *only ever refuses* a tool that sits above the authorized ceiling — it
/// never substitutes a different tool, model, or runtime. It is therefore
/// incapable of a silent model/runtime fallback (that policy lives in
/// `runtime/policy/no_silent_fallback.rs` and is untouched here). Below/at the
/// ceiling the dispatch proceeds; mutating-tool approval is owned by the
/// caller's existing confirm gate, not by this refusal.
fn enforce_autonomy_posture(
    descriptor: &ToolDescriptor,
    posture: crate::modules::autonomy::AutonomyPosture,
) -> Result<()> {
    use crate::modules::autonomy::{gate_descriptor, AutonomyDecision};
    match gate_descriptor(descriptor, posture) {
        AutonomyDecision::Refuse { needed, ceiling } => {
            Err(crate::modules::autonomy::AutonomyRefusal {
                tool_name: descriptor.name.clone(),
                needed,
                ceiling,
            }
            .into())
        }
        AutonomyDecision::RefuseUnclassified => {
            anyhow::bail!(
                "{} has no descriptor-owned autonomy phase for its {:?} effect; refusing dispatch",
                descriptor.name,
                descriptor.effect
            )
        }
        // `enforce_descriptor_context` already verified the authorization
        // proof before the autonomy ceiling was evaluated.
        AutonomyDecision::Allow | AutonomyDecision::RequireApproval => Ok(()),
    }
}

fn enforce_descriptor_context(
    descriptor: &ToolDescriptor,
    ctx: &ToolExecutionContext<'_>,
    operation_binding: &[u8; 32],
) -> Result<()> {
    if descriptor.workspace_requirement == WorkspaceRequirement::Required && ctx.workspace.is_none()
    {
        anyhow::bail!("{} requires an explicit active workspace", descriptor.name)
    }
    if !descriptor.headless
        && !ctx
            .authorization
            .is_interactive_for(operation_binding)
    {
        anyhow::bail!(
            "{} is shell-only (headless=false) and requires interactive dispatch",
            descriptor.name
        )
    }
    Ok(())
}

fn enforce_descriptor_finding_store(
    descriptor: &ToolDescriptor,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if descriptor.finding_store_requirement == FindingStoreRequirement::Required
        && ctx.findings_store.is_none()
    {
        anyhow::bail!("{} requires an active findings store", descriptor.name)
    }
    Ok(())
}

fn enforce_descriptor_approval(
    descriptor: &ToolDescriptor,
    ctx: &ToolExecutionContext<'_>,
    operation_binding: &[u8; 32],
) -> Result<()> {
    if descriptor.approval == ApprovalPolicy::Explicit
        && !ctx.authorization.is_explicit_for(operation_binding)
    {
        anyhow::bail!(
            "{} requires explicit operator authorization before dispatch",
            descriptor.name
        )
    }
    Ok(())
}

fn runtime_requirement_is_deferred_to_executor(name: &str) -> bool {
    matches!(
        name,
        "carlini-threat-hunt:run"
            | "offense-review:threat-hunt"
            | "patch:finding"
            | "prompt-armor:analyze"
            | "prompt-armor:attack"
            | "prompt-armor:scan"
            | "verify:finding"
    )
}

fn prepare_input_with_stored_options(
    name: &str,
    input: Value,
    option_store: Option<&ToolOptionStore>,
    tool: Option<&ToolDescriptor>,
) -> Result<Value> {
    match (option_store, tool) {
        (Some(store), Some(tool)) => {
            validate_workspace_stored_options(store, name, tool)?;
            store.effective_tool_input_with_stored_key_resolver(name, input, |option_name| {
                tool.options
                    .iter()
                    .find(|spec| spec.matches_name_or_alias(option_name))
                    .map(|spec| spec.name.clone())
            })
        }
        (Some(store), None) => store.effective_tool_input(name, input),
        (None, _) => Ok(input),
    }
}

fn validate_workspace_stored_options(
    store: &ToolOptionStore,
    tool_name: &str,
    tool: &ToolDescriptor,
) -> Result<()> {
    let values = store.stored_values_for_scope(crate::options::OptionScope::Workspace, tool_name);
    for option_name in values.keys() {
        if option_name.eq_ignore_ascii_case("model")
            || option_name.to_ascii_uppercase().starts_with("MODEL_")
        {
            anyhow::bail!(
                "workspace options may not steer model policy: {tool_name} option {option_name:?}"
            )
        }
        let Some(spec) = tool
            .options
            .iter()
            .find(|spec| spec.matches_name_or_alias(option_name))
        else {
            continue;
        };
        if spec
            .path_semantics
            .is_some_and(PathSemantics::forbids_workspace_storage)
        {
            anyhow::bail!(
                "workspace options may not set {} path option {:?} for {tool_name}",
                path_semantics_label(spec.path_semantics.unwrap()),
                spec.name
            )
        }
    }
    Ok(())
}

fn normalize_workspace_path_options(
    registry: &ModuleRegistry,
    tool_name: &str,
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
    enforce_authorization: bool,
    operation_binding: Option<&[u8; 32]>,
) -> Result<()> {
    let tool = registry
        .resolve_tool(tool_name)
        .with_context(|| format!("{tool_name:?} has no descriptor for path validation"))?;
    for option in tool
        .options
        .iter()
        .filter(|option| option.option_type == OptionType::Path)
    {
        normalize_declared_path_option(
            tool_name,
            option,
            input,
            ctx,
            enforce_authorization,
            operation_binding,
        )?;
    }
    normalize_file_reference_options(tool_name, tool, input, ctx)?;
    Ok(())
}

fn normalize_declared_path_option(
    tool_name: &str,
    option: &OptionSpec,
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
    enforce_authorization: bool,
    operation_binding: Option<&[u8; 32]>,
) -> Result<()> {
    let semantics = option.path_semantics.with_context(|| {
        format!(
            "{} path option {:?} is missing required path semantics",
            tool_name, option.name
        )
    })?;
    let path = input
        .get(&option.name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| default_workspace_path_value(option, ctx));
    let Some(path) = path else { return Ok(()) };
    input[&option.name] = Value::String(normalize_path_option(
        tool_name,
        &option.name,
        &path,
        semantics,
        ctx,
        enforce_authorization,
        operation_binding,
    )?);
    Ok(())
}

fn default_workspace_path_value(
    option: &OptionSpec,
    ctx: &ToolExecutionContext<'_>,
) -> Option<String> {
    (option.path_semantics == Some(PathSemantics::WorkspaceRead)
        && matches!(option.name.as_str(), "target" | "cwd"))
    .then(|| {
        ctx.workspace
            .map(|workspace| workspace.root().display().to_string())
    })
    .flatten()
}

fn normalize_file_reference_options(
    tool_name: &str,
    tool: &ToolDescriptor,
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    for option in &tool.options {
        let Some(semantics) = option.file_reference_semantics else {
            continue;
        };
        normalize_file_reference_option(tool_name, option, semantics, input, ctx)?;
    }
    Ok(())
}

fn normalize_file_reference_option(
    tool_name: &str,
    option: &OptionSpec,
    semantics: FileReferenceSemantics,
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    match semantics {
        FileReferenceSemantics::InlineOrWorkspaceFile => {
            normalize_single_file_reference(tool_name, option, input, ctx)
        }
        FileReferenceSemantics::InlineOrWorkspaceFiles => {
            normalize_file_reference_list(tool_name, option, input, ctx)
        }
    }
}

fn normalize_single_file_reference(
    tool_name: &str,
    option: &OptionSpec,
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(value) = input
        .get(&option.name)
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Ok(());
    };
    input[&option.name] = Value::String(normalize_inline_or_workspace_file(
        tool_name,
        &option.name,
        &value,
        ctx,
    )?);
    Ok(())
}

fn normalize_file_reference_list(
    tool_name: &str,
    option: &OptionSpec,
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let Some(values) = input.get(&option.name).and_then(Value::as_array).cloned() else {
        return Ok(());
    };
    let normalized = values
        .into_iter()
        .map(|value| normalize_file_reference_value(tool_name, option, value, ctx))
        .collect::<Result<Vec<_>>>()?;
    input[&option.name] = Value::Array(normalized);
    Ok(())
}

fn normalize_file_reference_value(
    tool_name: &str,
    option: &OptionSpec,
    value: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match value {
        Value::String(value) => {
            normalize_inline_or_workspace_file(tool_name, &option.name, &value, ctx)
                .map(Value::String)
        }
        value => Ok(value),
    }
}

fn normalize_inline_or_workspace_file(
    tool_name: &str,
    option_name: &str,
    value: &str,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    if !crate::options::looks_like_prompt_path(value) {
        return Ok(value.to_string());
    }
    normalize_workspace_path(
        tool_name,
        option_name,
        value,
        required_workspace_root(tool_name, option_name, ctx)?,
        true,
    )
}

fn normalize_path_option(
    tool_name: &str,
    option_name: &str,
    path: &str,
    semantics: PathSemantics,
    ctx: &ToolExecutionContext<'_>,
    enforce_authorization: bool,
    operation_binding: Option<&[u8; 32]>,
) -> Result<String> {
    if path.trim().is_empty() {
        anyhow::bail!("{tool_name} {option_name} path may not be blank")
    }
    match semantics {
        PathSemantics::WorkspaceRead => normalize_workspace_read_path(tool_name, option_name, path, ctx),
        PathSemantics::StateWrite => normalize_state_write_path(tool_name, option_name, path, ctx),
        PathSemantics::TargetWrite => normalize_target_write_path(
            tool_name, option_name, path, ctx, enforce_authorization, operation_binding,
        ),
        PathSemantics::ExternalRead => normalize_external_read_path(tool_name, option_name, path),
        PathSemantics::ExternalWrite => normalize_external_write_path(
            tool_name, option_name, path, ctx, enforce_authorization, operation_binding,
        ),
        PathSemantics::Executable => normalize_executable_path(tool_name, option_name, path),
    }
}

fn normalize_workspace_read_path(
    tool_name: &str,
    option_name: &str,
    path: &str,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    normalize_workspace_path(
        tool_name,
        option_name,
        path,
        required_workspace_root(tool_name, option_name, ctx)?,
        true,
    )
}

fn normalize_target_write_path(
    tool_name: &str,
    option_name: &str,
    path: &str,
    ctx: &ToolExecutionContext<'_>,
    enforce_authorization: bool,
    operation_binding: Option<&[u8; 32]>,
) -> Result<String> {
    let normalized = normalize_workspace_path(
        tool_name,
        option_name,
        path,
        required_workspace_root(tool_name, option_name, ctx)?,
        false,
    )?;
    enforce_path_write_authorization(
        tool_name,
        option_name,
        ctx,
        enforce_authorization,
        operation_binding,
    )?;
    Ok(normalized)
}

fn normalize_external_write_path(
    tool_name: &str,
    option_name: &str,
    path: &str,
    ctx: &ToolExecutionContext<'_>,
    enforce_authorization: bool,
    operation_binding: Option<&[u8; 32]>,
) -> Result<String> {
    enforce_path_write_authorization(
        tool_name,
        option_name,
        ctx,
        enforce_authorization,
        operation_binding,
    )?;
    let path = std::path::Path::new(path);
    let normalized = match path.is_absolute() {
        true => path.to_path_buf(),
        false => required_workspace_root(tool_name, option_name, ctx)?.join(path),
    };
    Ok(normalized.display().to_string())
}

fn normalize_state_write_path(
    tool_name: &str,
    option_name: &str,
    path: &str,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    let workspace_root = required_workspace_root(tool_name, option_name, ctx)?;
    let raw = std::path::Path::new(path);
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        workspace_root.join(raw)
    };
    let state_root = workspace_root.join(crate::workspace::KUZUSHI_STATE_DIR);
    if !candidate.starts_with(&state_root) {
        anyhow::bail!(
            "{tool_name} {option_name} state-write path {} must stay under {}",
            candidate.display(),
            state_root.display()
        )
    }
    normalize_workspace_path(tool_name, option_name, path, workspace_root, false)
}

fn enforce_path_write_authorization(
    tool_name: &str,
    option_name: &str,
    ctx: &ToolExecutionContext<'_>,
    enforce_authorization: bool,
    operation_binding: Option<&[u8; 32]>,
) -> Result<()> {
    let explicitly_authorized = operation_binding
        .is_some_and(|binding| ctx.authorization.is_explicit_for(binding));
    if enforce_authorization && !explicitly_authorized {
        anyhow::bail!(
            "{tool_name} {option_name} requires explicit operator authorization for a non-state write path"
        )
    }
    Ok(())
}

fn required_workspace_root<'a>(
    tool_name: &str,
    option_name: &str,
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a std::path::Path> {
    ctx.workspace
        .map(crate::workspace::WorkspaceTarget::root)
        .with_context(|| format!("{tool_name} {option_name} requires an explicit workspace"))
}

fn normalize_workspace_path(
    tool_name: &str,
    option_name: &str,
    path: &str,
    workspace_root: &std::path::Path,
    must_exist: bool,
) -> Result<String> {
    let path = std::path::Path::new(path);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("{tool_name} {option_name} path may not contain ..")
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    };
    let canonical =
        canonicalize_workspace_candidate(&candidate, must_exist).with_context(|| {
            format!(
                "{tool_name} {option_name} path {} could not be resolved inside workspace {}",
                candidate.display(),
                workspace_root.display()
            )
        })?;
    if canonical.starts_with(workspace_root) {
        return Ok(canonical.display().to_string());
    }
    anyhow::bail!(
        "{tool_name} {option_name} path {} is outside canonical workspace {}",
        canonical.display(),
        workspace_root.display()
    )
}

fn canonicalize_workspace_candidate(
    candidate: &std::path::Path,
    must_exist: bool,
) -> Result<std::path::PathBuf> {
    if must_exist || candidate.exists() {
        return candidate.canonicalize().map_err(Into::into);
    }
    let mut ancestor = candidate.parent();
    while let Some(path) = ancestor {
        if path.exists() {
            let canonical = path.canonicalize()?;
            let suffix = candidate.strip_prefix(path)?;
            return Ok(canonical.join(suffix));
        }
        ancestor = path.parent();
    }
    anyhow::bail!("path has no existing ancestor")
}

fn normalize_external_read_path(tool_name: &str, option_name: &str, path: &str) -> Result<String> {
    let canonical = std::path::Path::new(path)
        .canonicalize()
        .with_context(|| format!("{tool_name} {option_name} external read path is unavailable"))?;
    Ok(canonical.display().to_string())
}

fn normalize_executable_path(tool_name: &str, option_name: &str, path: &str) -> Result<String> {
    if path.trim().is_empty() {
        anyhow::bail!("{tool_name} {option_name} executable path may not be empty")
    }
    if path.contains(std::path::MAIN_SEPARATOR) {
        let canonical = std::path::Path::new(path).canonicalize().with_context(|| {
            format!("{tool_name} {option_name} executable path could not be resolved")
        })?;
        return Ok(canonical.display().to_string());
    }
    Ok(path.to_string())
}

fn path_semantics_label(semantics: PathSemantics) -> &'static str {
    match semantics {
        PathSemantics::WorkspaceRead => "workspace-read",
        PathSemantics::StateWrite => "state-write",
        PathSemantics::TargetWrite => "target-write",
        PathSemantics::ExternalRead => "external-read",
        PathSemantics::ExternalWrite => "external-write",
        PathSemantics::Executable => "executable",
    }
}

fn input_with_prompt_file_default(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let Some(default) = prompt_file_default_for_tool(name) else {
        return Ok(input);
    };
    apply_prompt_file_default(input, ctx, default)
}

fn input_with_declared_prompt_defaults(
    registry: &ModuleRegistry,
    name: &str,
    mut input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let Some(descriptor) = registry.resolve_tool(name) else {
        return Ok(input);
    };
    for prompt in &descriptor.prompts {
        input = apply_declared_prompt_file_default(input, ctx, prompt)?;
    }
    Ok(input)
}

fn apply_declared_prompt_file_default(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    prompt: &PromptSpec,
) -> Result<Value> {
    let Value::Object(mut object) = input else {
        return Ok(input);
    };
    if object.contains_key(&prompt.option_key) {
        return Ok(Value::Object(object));
    }
    let Some(workspace) = ctx.workspace else {
        return Ok(Value::Object(object));
    };
    let path =
        crate::options::prompt_override_path(workspace.root(), &prompt.module_id, &prompt.verb);
    match crate::options::read_workspace_prompt_file(workspace.root(), &path) {
        Ok(text) if !text.trim().is_empty() => {
            object.insert(prompt.option_key.clone(), Value::String(text));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Could not read {} from {}", prompt.option_key, path.display())
            });
        }
    }
    Ok(Value::Object(object))
}

#[derive(Clone, Copy)]
struct PromptFileDefault {
    module_id: &'static str,
    verb: &'static str,
    option_key: &'static str,
}

fn prompt_file_default_for_tool(name: &str) -> Option<PromptFileDefault> {
    match name {
        "triage:run" => Some(prompt_file_default("triage", "run", "TRIAGE_PROMPT")),
        "verify:finding" => Some(prompt_file_default("verify", "finding", "VERIFY_PROMPT")),
        "threat-model:build" => Some(prompt_file_default(
            "threat-model",
            "build",
            "THREAT_MODEL_PROMPT",
        )),
        "taint-iris:hunt" => Some(prompt_file_default(
            "taint-iris",
            "hunt",
            "TAINT_IRIS_PROMPT",
        )),
        "carlini-threat-hunt:run" => Some(prompt_file_default(
            "carlini-threat-hunt",
            "run",
            "CARLINI_THREAT_HUNT_PROMPT",
        )),
        _ => None,
    }
}

fn prompt_file_default(
    module_id: &'static str,
    verb: &'static str,
    option_key: &'static str,
) -> PromptFileDefault {
    PromptFileDefault {
        module_id,
        verb,
        option_key,
    }
}

fn apply_prompt_file_default(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    default: PromptFileDefault,
) -> Result<Value> {
    let Value::Object(mut object) = input else {
        return Ok(input);
    };
    if object.contains_key(default.option_key) {
        return Ok(Value::Object(object));
    }
    if let Some(text) = read_prompt_file_default(ctx, default)? {
        object.insert(default.option_key.to_string(), Value::String(text));
    }
    Ok(Value::Object(object))
}

fn read_prompt_file_default(
    ctx: &ToolExecutionContext<'_>,
    default: PromptFileDefault,
) -> Result<Option<String>> {
    let Some(workspace) = ctx.workspace else {
        return Ok(None);
    };
    let path =
        crate::options::prompt_override_path(workspace.root(), default.module_id, default.verb);
    match crate::options::read_workspace_prompt_file(workspace.root(), &path) {
        Ok(text) if !text.trim().is_empty() => Ok(Some(text)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "Could not read {} from {}",
                default.option_key,
                path.display()
            )
        }),
    }
}

fn scoped_tool_trace(
    ctx: &ToolExecutionContext<'_>,
    name: &str,
) -> Option<crate::run_artifacts::TraceHandle> {
    ctx.trace
        .map(|handle| handle.for_module(module_id_from_tool_name(name)))
}

fn scoped_tool_context<'scope>(
    ctx: &'scope ToolExecutionContext<'_>,
    trace: &'scope crate::run_artifacts::TraceHandle,
) -> ToolExecutionContext<'scope> {
    ToolExecutionContext {
        config: ctx.config,
        workspace: ctx.workspace,
        findings_store: ctx.findings_store,
        trace: Some(trace),
        cancellation: ctx.cancellation,
        authorization: ctx.authorization.clone(),
    }
}

fn traced_tool_runtime<'scope>(
    runtime: Option<&'scope dyn AgentRuntime>,
    trace: Option<&'scope crate::run_artifacts::TraceHandle>,
) -> Option<crate::runtime::TracedRuntime<'scope>> {
    match (runtime, trace) {
        (Some(runtime), Some(trace)) => {
            Some(crate::runtime::TracedRuntime::new(runtime, trace.clone()))
        }
        _ => None,
    }
}

fn active_tool_runtime<'scope>(
    runtime: Option<&'scope dyn AgentRuntime>,
    traced_runtime: Option<&'scope crate::runtime::TracedRuntime<'scope>>,
) -> Option<&'scope dyn AgentRuntime> {
    traced_runtime
        .map(|runtime| runtime as &dyn AgentRuntime)
        .or(runtime)
}

#[cfg(test)]
mod prompt_file_default_tests {
    use super::*;
    use crate::{V2Config, WorkspaceTarget};

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    #[test]
    fn direct_tool_prompt_file_default_is_injected() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let path = crate::options::prompt_override_path(temp.path(), "triage", "run");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "prioritize exploitability\n").unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let input = input_with_prompt_file_default("triage:run", json!({}), &ctx).unwrap();

        assert_eq!(input["TRIAGE_PROMPT"], json!("prioritize exploitability\n"));
    }

    #[test]
    fn direct_tool_prompt_file_default_keeps_explicit_input() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let path = crate::options::prompt_override_path(temp.path(), "triage", "run");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "file prompt\n").unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let input = input_with_prompt_file_default(
            "triage:run",
            json!({"TRIAGE_PROMPT": "explicit prompt"}),
            &ctx,
        )
        .unwrap();

        assert_eq!(input["TRIAGE_PROMPT"], json!("explicit prompt"));
    }

    #[test]
    fn agentic_sast_prompt_file_default_is_injected() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let path =
            crate::options::prompt_override_path(temp.path(), "agentic-sast", "scan");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "review authorization boundaries\n").unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let registry = ModuleRegistry::with_v2_builtins();
        let input = registry
            .prepare_tool_input_for_dispatch("agentic-sast:scan", json!({}), &ctx, None)
            .unwrap();

        assert_eq!(
            input["AGENTIC_SAST_PROMPT"],
            json!("review authorization boundaries\n")
        );
    }

    #[test]
    fn threat_model_prompt_file_default_is_injected() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let path = crate::options::prompt_override_path(temp.path(), "threat-model", "build");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "focus callback replay threats\n").unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let input = input_with_prompt_file_default("threat-model:build", json!({}), &ctx).unwrap();

        assert_eq!(
            input["THREAT_MODEL_PROMPT"],
            json!("focus callback replay threats\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn automatic_prompt_symlink_is_rejected_before_runtime_and_cas() {
        struct RuntimeMustNotRun;

        impl crate::runtime::AgentRuntime for RuntimeMustNotRun {
            fn triage_finding_blocking(
                &self,
                _request: crate::runtime::TriageRequest,
            ) -> anyhow::Result<crate::findings::TriageOutcome> {
                panic!("prompt validation must run before the agent runtime")
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside-secret.txt");
        let workspace_root = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace_root).unwrap();
        std::fs::write(&outside, "CAS-MUST-NOT-CONTAIN-THIS-SECRET").unwrap();
        let prompt = crate::options::prompt_override_path(&workspace_root, "triage", "run");
        std::fs::create_dir_all(prompt.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &prompt).unwrap();
        let workspace = WorkspaceTarget::new(&workspace_root).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let error = ModuleRegistry::with_v2_builtins()
            .execute_tool_with_runtime(
                "triage:run",
                json!({}),
                &ctx,
                Some(&RuntimeMustNotRun),
            )
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(!message.contains("CAS-MUST-NOT-CONTAIN-THIS-SECRET"));
        assert!(!crate::workspace::workspace_objects_dir(&workspace_root).exists());
    }
}

#[cfg(test)]
mod autonomy_gate_dispatch_tests {
    use crate::modules::autonomy::AutonomyPosture;
    use crate::modules::registry::ModuleRegistry;
    use crate::{V2Config, WorkspaceTarget};
    use serde_json::json;

    fn ctx_with_posture<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> crate::ToolExecutionContext<'a> {
        crate::ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    #[test]
    fn fix_tool_is_refused_under_hunt_posture_with_actionable_message() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut config = V2Config::default();
        config.autonomy = AutonomyPosture::Hunt;
        let ctx = ctx_with_posture(&config, &workspace);

        let error = registry
            .dispatch_prepared_tool_with_runtime(
                "patch:finding",
                json!({"fingerprint": "finding-1"}),
                &ctx,
                None,
            )
            .expect_err("patch:finding must be refused above the ceiling");
        let message = error.to_string();
        assert!(message.contains("patch:finding"), "{message}");
        assert!(message.contains("posture"), "{message}");
        assert!(message.contains("raise"), "{message}");
    }

    #[test]
    fn refusal_fires_before_the_runtime_requirement_check() {
        // triage:run needs a runtime AND is above a Hunt ceiling; the posture
        // refusal must win so the operator sees the authorization message, not
        // a runtime error.
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut config = V2Config::default();
        config.autonomy = AutonomyPosture::Hunt;
        let ctx = ctx_with_posture(&config, &workspace);

        let error = registry
            .dispatch_prepared_tool_with_runtime("triage:run", json!({}), &ctx, None)
            .expect_err("triage:run must be refused above the ceiling");
        let message = error.to_string();
        assert!(message.contains("raise posture"), "{message}");
        assert!(!message.contains("requires an agent runtime"), "{message}");
    }

    #[test]
    fn default_fix_posture_leaves_runtime_requirement_as_the_gate() {
        // With the default (Fix) posture nothing is refused by autonomy, so the
        // existing runtime-requirement error is what surfaces — proving the
        // gate is behavior-preserving for headless callers.
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ctx_with_posture(&config, &workspace);

        let error = registry
            .dispatch_prepared_tool_with_runtime("triage:run", json!({}), &ctx, None)
            .expect_err("triage:run still needs a runtime under Fix");
        let message = error.to_string();
        assert!(message.contains("requires an agent runtime"), "{message}");
        assert!(!message.contains("raise posture"), "{message}");
    }

    #[test]
    fn explicit_effect_requires_authorization_proof() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ctx_with_posture(&config, &workspace);

        let error = registry
            .dispatch_prepared_tool_with_runtime(
                "patch:finding",
                json!({"fingerprint": "finding-1"}),
                &ctx,
                None,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("explicit operator authorization"), "{error}");
    }

    #[test]
    fn prompt_armor_config_init_cannot_write_target_without_authorization() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ctx_with_posture(&config, &workspace);

        let error = registry
            .execute_tool(
                "prompt-armor:config",
                json!({"target": temp.path(), "action": "init"}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("explicit operator authorization"), "{error}");
        assert!(!temp.path().join("promptarmor.yaml").exists());
    }

    #[test]
    fn artifact_writers_cannot_run_under_automated_authorization() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ctx_with_posture(&config, &workspace);

        for tool_name in ["x-ray:run", "prompt-armor:scan"] {
            let error = registry
                .execute_tool(tool_name, json!({"target": temp.path()}), &ctx)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("explicit operator authorization"),
                "{tool_name}: {error}"
            );
        }
    }

    #[test]
    fn android_decompile_writers_require_operation_bound_authorization() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("sample.apk");
        std::fs::write(&apk, b"PK\x03\x04").unwrap();
        let apk_input = apk.display().to_string();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ctx_with_posture(&config, &workspace);

        for tool_name in ["android-apk:prepare", "android-apk:scan"] {
            let error = registry
                .execute_tool(tool_name, json!({"apk": apk_input.clone()}), &ctx)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("explicit operator authorization"),
                "{tool_name}: {error}"
            );
        }
        assert!(!temp.path().join("android-decompiled").exists());
    }

    #[test]
    fn cve_network_fetch_cannot_run_under_automated_authorization() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ctx_with_posture(&config, &workspace);

        let error = registry
            .execute_tool("ndiff:fetch-cve", json!({"id": "CVE-2026-0001"}), &ctx)
            .unwrap_err()
            .to_string();

        assert!(error.contains("explicit operator authorization"), "{error}");
    }
}

#[cfg(test)]
mod path_and_workspace_option_policy_tests {
    use super::*;
    use crate::{OptionScope, OptionTarget, V2Config, WorkspaceTarget};

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: ExecutionAuthorization::default(),
        }
    }

    #[test]
    fn project_store_cannot_supply_write_path() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("codeql:create-db".to_string()),
            "outputPath",
            json!("/tmp/repo-controlled-codeql-db"),
        );

        let error = registry
            .prepare_dispatch_input(
                "codeql:create-db",
                json!({"target": temp.path()}),
                &ctx,
                Some(&store),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("state-write"), "{error}");
    }

    #[test]
    fn project_store_cannot_steer_model() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("threat-model:build".to_string()),
            "model",
            json!("attacker:steered-model"),
        );

        let error = registry
            .prepare_dispatch_input("threat-model:build", json!({}), &ctx, Some(&store))
            .unwrap_err()
            .to_string();

        assert!(error.contains("may not steer model policy"), "{error}");
    }

    #[test]
    fn persisted_project_options_file_cannot_steer_model() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let project_path = temp.path().join("project-options.json");
        let global_path = temp.path().join("missing-global-options.json");
        let mut project = ToolOptionStore::new();
        project.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("triage:run".to_string()),
            "model",
            json!("attacker:project-model"),
        );
        project.save_to_path(&project_path).unwrap();
        let loaded = ToolOptionStore::load_persistent(&global_path, Some(&project_path)).unwrap();

        let error = registry
            .prepare_dispatch_input("triage:run", json!({}), &ctx, Some(&loaded))
            .unwrap_err()
            .to_string();

        assert!(error.contains("may not steer model policy"), "{error}");
    }

    #[test]
    fn project_prompt_option_cannot_read_host_file() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("triage:run".to_string()),
            "TRIAGE_PROMPT",
            json!(outside.path()),
        );

        let error = registry
            .prepare_dispatch_input("triage:run", json!({}), &ctx, Some(&store))
            .unwrap_err()
            .to_string();

        assert!(error.contains("outside canonical workspace"), "{error}");
    }

    #[test]
    fn threat_model_seed_file_is_workspace_confined() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let error = registry
            .prepare_dispatch_input(
                "threat-model:build",
                json!({"seed": [outside.path()]}),
                &ctx,
                None,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("outside canonical workspace"), "{error}");
    }

    #[test]
    fn every_declared_path_is_contained_not_just_target_and_cwd() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let error = registry
            .prepare_dispatch_input(
                "codeql:create-db",
                json!({"target": temp.path(), "outputPath": "/tmp/outside-codeql-db"}),
                &ctx,
                None,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("state-write path"), "{error}");
    }

    #[test]
    fn relative_target_is_normalized_against_workspace_once() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("subdir")).unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let prepared = registry
            .prepare_dispatch_input(
                "systems-hunt:systems-hunt",
                json!({"target": "subdir"}),
                &ctx,
                None,
            )
            .unwrap();

        assert_eq!(
            prepared.value()["target"],
            json!(workspace.root().join("subdir").display().to_string())
        );
    }

    #[test]
    fn blank_target_is_rejected_at_canonical_preparation() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let error = registry
            .prepare_dispatch_input("taint-iris:hunt", json!({"target": ""}), &ctx, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("path may not be blank"), "{error}");
    }
}

/// Derive a module id from a qualified tool name (`semgrep:scan` -> `semgrep`).
/// Returns the full name when the colon is missing so unprefixed entries still
/// flow through with a stable label.
pub fn module_id_from_tool_name(name: &str) -> &str {
    name.split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or(name)
}

#[cfg(test)]
mod module_id_derivation_tests {
    use super::module_id_from_tool_name;

    #[test]
    fn module_id_strips_first_colon() {
        assert_eq!(module_id_from_tool_name("semgrep:scan"), "semgrep");
        assert_eq!(module_id_from_tool_name("triage:run"), "triage");
        assert_eq!(
            module_id_from_tool_name("agentic-sast:scan"),
            "agentic-sast"
        );
    }

    #[test]
    fn module_id_handles_unprefixed() {
        assert_eq!(module_id_from_tool_name("smoke"), "smoke");
    }

    #[test]
    fn module_id_only_strips_first_segment() {
        // Hidden internal nodes like `pipeline:taint-cwe-select` should still
        // collapse to their module id.
        assert_eq!(
            module_id_from_tool_name("pipeline:taint-cwe-select"),
            "pipeline"
        );
        assert_eq!(
            module_id_from_tool_name("systems-hunt:systems-trigger-synth"),
            "systems-hunt"
        );
    }
}
