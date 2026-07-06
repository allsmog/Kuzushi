use super::*;
use std::sync::mpsc::{Receiver, TryRecvError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DrainStatus {
    BudgetExhausted,
    Empty,
    Disconnected,
}

pub(super) fn default_activity_run_id() -> String {
    format!(
        "manual-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    )
}

pub(super) fn collect_current_events<T>(
    rx: Option<&Receiver<StampedEvent<T>>>,
    generation: Option<WorkerGeneration>,
    limit: usize,
) -> (Vec<T>, DrainStatus) {
    let Some(rx) = rx else {
        return (Vec::new(), DrainStatus::Empty);
    };
    let Some(generation) = generation else {
        return (Vec::new(), DrainStatus::Empty);
    };
    let mut events = Vec::with_capacity(limit);
    let mut received = 0;
    while received < limit {
        match rx.try_recv() {
            Ok(event) => {
                received += 1;
                if event.generation == generation {
                    events.push(event.payload);
                }
            }
            Err(TryRecvError::Empty) => return (events, DrainStatus::Empty),
            Err(TryRecvError::Disconnected) => return (events, DrainStatus::Disconnected),
        }
    }
    (events, DrainStatus::BudgetExhausted)
}

pub(super) fn can_clear_channel(status: DrainStatus) -> bool {
    status != DrainStatus::BudgetExhausted
}

pub(super) fn disconnected_without_events<T>(events: &[T], status: DrainStatus) -> bool {
    events.is_empty() && status == DrainStatus::Disconnected
}

pub(super) fn disconnected_worker_message(worker: &str) -> String {
    format!("{worker} worker disconnected before reporting completion")
}

pub(super) fn disconnected_agent_audit(app: &ShellApp) -> AgentCallAudit {
    let model = app
        .config
        .model
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let provider = if model == "unknown" {
        "unknown".to_string()
    } else {
        kuzushi_core::model_provider(&model).to_string()
    };
    AgentCallAudit {
        model,
        provider,
        prompt_hash: "disconnected-worker".to_string(),
        cost_usd: None,
    }
}
