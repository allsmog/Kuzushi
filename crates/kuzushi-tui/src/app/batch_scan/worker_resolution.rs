use anyhow::Result;
use kuzushi_core::ModuleRegistry;
use serde_json::Value;

/// Narrow TUI adapter for batch worker clamping. Core owns every task/resource
/// claim; this layer only prevents displaying more workers than planned jobs.
pub(crate) fn resolve_batch_workers(
    registry: &ModuleRegistry,
    prepared_input: &Value,
    requested_workers: usize,
    trials: usize,
) -> Result<BatchWorkerResolution> {
    let core = kuzushi_core::capabilities::campaign::resolve_parallel_safety(
        registry,
        "sast:scan",
        prepared_input,
        requested_workers,
    )?;
    let effective_workers = core.effective_workers.min(trials.max(1));
    let trial_reason = (effective_workers < core.effective_workers).then(|| {
        format!(
            "workers clamped to {effective_workers}: only {trials} logical trial(s) are planned"
        )
    });
    Ok(BatchWorkerResolution {
        effective_workers,
        reason: core.clamp_reason.or(trial_reason),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchWorkerResolution {
    pub(crate) effective_workers: usize,
    pub(crate) reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_only_to_available_logical_trials() {
        let registry = ModuleRegistry::with_v2_builtins();
        let input = serde_json::json!({"taskMode": "manual", "tasks": ["semgrep"]});
        let resolution = resolve_batch_workers(&registry, &input, 8, 3).unwrap();
        assert_eq!(resolution.effective_workers, 3);
        assert!(resolution.reason.unwrap().contains("3 logical trial"));
    }

    #[test]
    fn unknown_task_uses_the_shared_fail_closed_reason() {
        let registry = ModuleRegistry::with_v2_builtins();
        let input = serde_json::json!({"taskMode": "manual", "tasks": ["new-scanner"]});
        let resolution = resolve_batch_workers(&registry, &input, 4, 10).unwrap();

        assert_eq!(resolution.effective_workers, 1);
        assert!(resolution.reason.unwrap().contains("new-scanner"));
    }
}
