use super::*;

pub(crate) fn unsafe_clone_runtime_ref(rt: &dyn AgentRuntime) -> std::sync::Arc<dyn AgentRuntime> {
    use std::sync::Arc;
    // SAFETY: BorrowedRuntime extends the lifetime to 'static via a raw
    // pointer. The caller owns the underlying runtime for the lifetime of
    // this call; the Arc never escapes the helper functions above (they
    // construct it and immediately consume it).
    struct BorrowedRuntime(*const (dyn AgentRuntime + 'static));
    unsafe impl Send for BorrowedRuntime {}
    unsafe impl Sync for BorrowedRuntime {}

    impl AgentRuntime for BorrowedRuntime {
        fn query_blocking(
            &self,
            req: crate::runtime::AgentQueryRequest,
        ) -> anyhow::Result<crate::runtime::AgentQueryResponse> {
            // SAFETY: pointer is valid for the lifetime of this trait
            // object — which the caller upholds by keeping the borrow
            // alive.
            unsafe { (*self.0).query_blocking(req) }
        }
        fn triage_finding_blocking(
            &self,
            req: crate::runtime::TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            unsafe { (*self.0).triage_finding_blocking(req) }
        }
        fn supports_tools(&self) -> bool {
            unsafe { (*self.0).supports_tools() }
        }
        fn next_step_blocking(
            &self,
            req: &crate::runtime::AgentToolLoopRequest,
            history: &[crate::runtime::LoopHistoryEntry],
        ) -> anyhow::Result<crate::runtime::AgentLoopStep> {
            unsafe { (*self.0).next_step_blocking(req, history) }
        }
    }

    let static_ref: *const (dyn AgentRuntime + 'static) =
        unsafe { std::mem::transmute::<*const dyn AgentRuntime, _>(rt as *const _) };
    Arc::new(BorrowedRuntime(static_ref))
}

pub(crate) fn router_module() -> BuiltinModule {
    use crate::agent_router::AgentRole;
    let mut model_specs: Vec<OptionSpec> = AgentRole::all()
        .iter()
        .map(|role| {
            let name = role.option_store_key();
            let description = format!(
                "Override model for the `{}` role. Format: provider:modelId. \
                 Settable from the shell with `setg {} <model>`. Wins over models.toml.",
                role.as_key(),
                name
            );
            opt(&name, OptionType::String, &description)
        })
        .collect();
    // Stable order across builds.
    model_specs.sort_by(|a, b| a.name.cmp(&b.name));

    builtin_module(
        "router",
        "Agent router",
        ModuleKind::Governance,
        "Per-role model routing. Set MODEL_<ROLE> via `setg` to override models.toml.",
        vec![tool_with_options(
            "router:show",
            "Show effective per-role model routing.",
            model_specs,
        )],
        vec![],
    )
}

pub(crate) fn smoke_module() -> BuiltinModule {
    builtin_module(
        "smoke",
        "Smoke tests",
        ModuleKind::Governance,
        "Diagnostic flows that exercise the bridge end-to-end without paying for a real scan.",
        vec![tool_with_options(
            "smoke:next-step",
            "Drive a 2-step tool-loop with an `echo` tool to verify next_step_blocking + run_tool_loop.",
            vec![opt(
                "phrase",
                OptionType::String,
                "Phrase the model is asked to echo back. Default: 'kuzushi-ok'.",
            )
            .default(serde_json::json!("kuzushi-ok"))],
        )],
        vec![],
    )
}
