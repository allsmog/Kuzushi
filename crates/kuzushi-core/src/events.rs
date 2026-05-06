use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

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
