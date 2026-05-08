use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Live progress state for an in-flight scan, emitted/updated by scan
/// orchestrators and consumed by the TUI to drive real `done/total`
/// progress bars instead of binary "running/done" placeholders.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub total: usize,
    pub done: usize,
    pub current_tool: Option<String>,
    pub current_target: Option<String>,
    /// Per-task progress: `{ "semgrep" => (done, total), ... }`.
    pub per_task: std::collections::BTreeMap<String, (usize, usize)>,
}

impl ScanProgress {
    pub fn percent(&self) -> u8 {
        if self.total == 0 {
            0
        } else {
            ((self.done as f64 / self.total as f64) * 100.0).round() as u8
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum CoreEvent {
    ScanStarted {
        run_id: String,
        target: String,
    },
    ScanFinished {
        run_id: String,
        findings_count: usize,
    },
    FindingStored {
        fingerprint: String,
        severity: String,
    },
    TriageFinished {
        fingerprint: String,
        verdict: String,
    },
    Status {
        message: String,
    },
}

pub trait EventSink: Send + Sync {
    fn publish(&self, event: CoreEvent);
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryEventSink {
    events: Arc<Mutex<Vec<CoreEvent>>>,
}

impl InMemoryEventSink {
    pub fn events(&self) -> Vec<CoreEvent> {
        self.events.lock().expect("event sink poisoned").clone()
    }
}

impl EventSink for InMemoryEventSink {
    fn publish(&self, event: CoreEvent) {
        self.events.lock().expect("event sink poisoned").push(event);
    }
}
