//! Finite accounting for scripted context queries, with no provider transport.
use crate::allowance::InvestigationWork;
use crate::runtime::scripted_fixture::{account_scripted_runtime, AccountedScriptedRuntime};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
use crate::{SpendLimiter, ToolExecutionContext};
use anyhow::Result;
pub(super) type AccountedRuntime<'a> = AccountedScriptedRuntime<'a>;

pub(super) fn account_runtime<'a>(
    ctx: &ToolExecutionContext<'_>,
    inner: &'a dyn AgentRuntime,
    calls: u32,
) -> AccountedRuntime<'a> {
    account_scripted_runtime(ctx, inner, InvestigationWork::Context, calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{V2Config, WorkspaceTarget};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScriptedQuery {
        calls: AtomicUsize,
        fail: bool,
    }

    impl AgentRuntime for ScriptedQuery {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(!self.fail, "scripted transport failure");
            Ok(AgentQueryResponse::default())
        }

        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::TriageOutcome> {
            anyhow::bail!("fixture does not triage")
        }
    }

    fn with_fixture(fail: bool, test: impl FnOnce(&ToolExecutionContext<'_>, &ScriptedQuery)) {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let config = V2Config {
            model: Some("openai:scripted-context".into()),
            ..Default::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let inner = ScriptedQuery {
            calls: AtomicUsize::new(0),
            fail,
        };
        test(&ctx, &inner);
    }

    fn request(ctx: &ToolExecutionContext<'_>) -> AgentQueryRequest {
        AgentQueryRequest::new(
            ctx.config.model.clone().unwrap(),
            ctx.workspace.unwrap().root(),
            "Owned scripted query",
            "No provider transport",
        )
    }

    fn snapshot(
        ctx: &ToolExecutionContext<'_>,
        runtime: &AccountedRuntime<'_>,
    ) -> crate::allowance::AllowanceSnapshot {
        SpendLimiter::open(ctx.workspace.unwrap().findings_db_path())
            .unwrap()
            .allowance_snapshot(&runtime.allowance_binding().unwrap().work().investigation_id)
            .unwrap()
    }

    #[test]
    fn finite_fixture_stops_before_an_extra_query_and_preserves_unknown_cost() {
        with_fixture(false, |ctx, inner| {
            let runtime = account_runtime(ctx, inner, 1);
            runtime.query_blocking(request(ctx)).unwrap();
            assert!(runtime.query_blocking(request(ctx)).is_err());
            assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
            let receipt = snapshot(ctx, &runtime);
            assert_eq!(receipt.committed_calls, 1);
            assert_eq!(receipt.unresolved_calls, 0);
            assert!(!receipt.cost.is_complete());
        });
    }

    #[test]
    fn failed_fixture_query_keeps_its_unresolved_consumed_reservation() {
        with_fixture(true, |ctx, inner| {
            let runtime = account_runtime(ctx, inner, 1);
            assert!(runtime.query_blocking(request(ctx)).is_err());
            assert!(runtime.query_blocking(request(ctx)).is_err());
            assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
            let receipt = snapshot(ctx, &runtime);
            assert_eq!(receipt.committed_calls, 1);
            assert_eq!(receipt.unresolved_calls, 1);
        });
    }

    #[test]
    fn fixture_model_change_is_refused_before_query_or_reservation() {
        with_fixture(false, |ctx, inner| {
            let runtime = account_runtime(ctx, inner, 1);
            let mut changed = request(ctx);
            changed.model = "openai:another-scripted-model".into();
            assert!(runtime.query_blocking(changed).is_err());
            assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
            assert_eq!(snapshot(ctx, &runtime).committed_calls, 0);
        });
    }
}
