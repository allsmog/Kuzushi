use super::output_contract::normalize_tool_output_contract;
use super::*;

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
        let input = self.prepare_tool_input_for_dispatch(name, input, ctx, option_store)?;
        self.dispatch_prepared_tool_with_runtime(name, input, ctx, runtime)
    }

    pub fn prepare_tool_input_for_dispatch(
        &self,
        name: &str,
        input: Value,
        ctx: &ToolExecutionContext<'_>,
        option_store: Option<&ToolOptionStore>,
    ) -> Result<Value> {
        let input = self.prepare_tool_input(name, input, option_store)?;
        input_with_prompt_file_default(name, input, ctx)
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
        enforce_autonomy_posture(name, ctx.config.autonomy)?;
        self.enforce_runtime_requirement(name, &input, runtime)?;
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
        let result = executor(self, name, &input, ctx, runtime);
        return result.map(|output| normalize_tool_output_contract(name, output));
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

/// Enforce the operator autonomy posture at the one shared dispatch boundary.
///
/// This *only ever refuses* a tool that sits above the authorized ceiling — it
/// never substitutes a different tool, model, or runtime. It is therefore
/// incapable of a silent model/runtime fallback (that policy lives in
/// `runtime/policy/no_silent_fallback.rs` and is untouched here). Below/at the
/// ceiling the dispatch proceeds; mutating-tool approval is owned by the
/// caller's existing confirm gate, not by this refusal.
fn enforce_autonomy_posture(
    name: &str,
    posture: crate::modules::autonomy::AutonomyPosture,
) -> Result<()> {
    use crate::modules::autonomy::{gate, AutonomyDecision};
    match gate(name, posture) {
        AutonomyDecision::Refuse { needed, ceiling } => {
            anyhow::bail!(posture_refusal_message(name, needed, ceiling))
        }
        AutonomyDecision::Allow | AutonomyDecision::RequireApproval => Ok(()),
    }
}

fn posture_refusal_message(
    name: &str,
    needed: crate::modules::autonomy::WorkflowPhase,
    ceiling: crate::modules::autonomy::WorkflowPhase,
) -> String {
    format!(
        "{name} is a {} action but autonomy posture is capped at {}; \
         raise posture (Ctrl+Up) to authorize",
        needed.word(),
        ceiling.word()
    )
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
            store.effective_tool_input_with_stored_filter(name, input, |option_name| {
                tool.options
                    .iter()
                    .any(|spec| spec.matches_name_or_alias(option_name))
            })
        }
        (Some(store), None) => store.effective_tool_input(name, input),
        (None, _) => Ok(input),
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
    match std::fs::read_to_string(&path) {
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
            .dispatch_prepared_tool_with_runtime("patch:finding", json!({}), &ctx, None)
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
