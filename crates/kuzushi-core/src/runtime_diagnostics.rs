use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const MAX_PENDING_DIAGNOSTICS: usize = 1_024;
const MAX_DIAGNOSTIC_SOURCE_BYTES: usize = 128;
const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 8 * 1_024;
const TRUNCATION_MARKER: &str = "… [truncated]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiagnostic {
    pub source: String,
    pub message: String,
}

#[derive(Default)]
struct DiagnosticQueue {
    pending: VecDeque<RuntimeDiagnostic>,
    dropped: usize,
}

impl DiagnosticQueue {
    fn record(&mut self, source: String, message: String) {
        if self.pending.len() >= MAX_PENDING_DIAGNOSTICS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.pending.push_back(RuntimeDiagnostic {
            source: bounded_text(normalize_source(source), MAX_DIAGNOSTIC_SOURCE_BYTES),
            message: bounded_text(message, MAX_DIAGNOSTIC_MESSAGE_BYTES),
        });
    }

    fn take(&mut self) -> Vec<RuntimeDiagnostic> {
        let mut diagnostics = self.pending.drain(..).collect::<Vec<_>>();
        if self.dropped > 0 {
            diagnostics.push(dropped_diagnostic(self.dropped));
            self.dropped = 0;
        }
        diagnostics
    }
}

pub(crate) fn record_runtime_diagnostic(source: impl Into<String>, message: impl Into<String>) {
    let mut queue = diagnostic_queue()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.record(source.into(), message.into());
}

/// Drain diagnostics produced by reusable core workers. CLI callers present
/// these on stderr; the interactive shell routes them through its in-memory
/// activity log instead of writing behind Ratatui's back.
pub fn take_runtime_diagnostics() -> Vec<RuntimeDiagnostic> {
    let mut queue = diagnostic_queue()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.take()
}

fn dropped_diagnostic(count: usize) -> RuntimeDiagnostic {
    RuntimeDiagnostic {
        source: "runtime".to_string(),
        message: format!(
            "{count} additional diagnostic(s) were dropped because the diagnostic queue was full"
        ),
    }
}

fn normalize_source(source: String) -> String {
    source
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&source)
        .to_string()
}

fn bounded_text(value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let content_limit = max_bytes.saturating_sub(TRUNCATION_MARKER.len());
    let mut end = content_limit.min(value.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}{TRUNCATION_MARKER}", &value[..end])
}

fn diagnostic_queue() -> &'static Mutex<DiagnosticQueue> {
    static QUEUE: OnceLock<Mutex<DiagnosticQueue>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(DiagnosticQueue::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_payloads_are_byte_bounded_on_utf8_boundaries() {
        let mut queue = DiagnosticQueue::default();
        queue.record("s".repeat(512), "日".repeat(4_096));
        let diagnostic = queue.take().pop().unwrap();

        assert!(diagnostic.source.len() <= MAX_DIAGNOSTIC_SOURCE_BYTES);
        assert!(diagnostic.message.len() <= MAX_DIAGNOSTIC_MESSAGE_BYTES);
        assert!(diagnostic.message.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn full_queue_reports_the_number_of_dropped_diagnostics() {
        let mut queue = DiagnosticQueue::default();
        for index in 0..MAX_PENDING_DIAGNOSTICS + 3 {
            queue.record("test".to_string(), index.to_string());
        }
        let diagnostics = queue.take();

        assert_eq!(diagnostics.len(), MAX_PENDING_DIAGNOSTICS + 1);
        assert!(diagnostics.last().unwrap().message.starts_with('3'));
        assert!(queue.take().is_empty());
    }
}
