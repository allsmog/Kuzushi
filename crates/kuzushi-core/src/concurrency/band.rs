use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Interactive operator action — patcher, deep auditor.
    High,
    /// Default for triage and classifier-gate calls.
    Normal,
    /// Background full-mode-multi chunks; yields to everything else.
    Lowest,
}

impl Priority {
    pub(crate) fn band(self) -> usize {
        match self {
            Priority::High => 0,
            Priority::Normal => 1,
            Priority::Lowest => 2,
        }
    }
}

tokio::task_local! {
    /// Current task's priority. Falls back to `Normal` when not scoped.
    pub static CURRENT_PRIORITY: Priority;
}

pub fn current_priority() -> Priority {
    CURRENT_PRIORITY
        .try_with(|p| *p)
        .unwrap_or(Priority::Normal)
}

pub async fn with_priority<F, T>(priority: Priority, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    CURRENT_PRIORITY.scope(priority, fut).await
}

pub fn default_concurrency_for(model: &str) -> usize {
    let m = model.to_ascii_lowercase();
    if m.contains("haiku") {
        80
    } else if m.contains("sonnet") {
        80
    } else if m.contains("opus") {
        60
    } else if m.contains("gemini") {
        600
    } else if m.contains("o3") || m.contains("o1") {
        700
    } else if m.contains("o4") || m.contains("gpt-4.1") || m.contains("gpt-4o") {
        500
    } else {
        // Conservative default for unknown models.
        16
    }
}

pub struct ModelGate {
    pub(crate) inner: Arc<ModelGateInner>,
}

pub(crate) struct ModelGateInner {
    pub(crate) semaphores: Mutex<BTreeMap<String, ModelSlot>>,
    pub(crate) overrides: Mutex<BTreeMap<String, usize>>,
}

#[derive(Clone)]
pub(crate) struct ModelSlot {
    pub(crate) sem: Arc<Semaphore>,
    pub(crate) queues: Arc<Mutex<[VecDeque<Arc<Notify>>; 3]>>,
    /// Notified whenever a permit is released back to the slot.
    pub(crate) permit_released: Arc<Notify>,
}
