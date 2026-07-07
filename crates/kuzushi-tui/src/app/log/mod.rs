use super::*;
pub(crate) use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const LOG_LINE_CAPACITY: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogState {
    lines: Vec<LogLine>,
    capacity: usize,
}

impl Default for LogState {
    fn default() -> Self {
        Self {
            lines: Vec::new(),
            capacity: LOG_LINE_CAPACITY,
        }
    }
}

impl LogState {
    pub(crate) fn push(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.lines.push(LogLine::new(prefix, body));
        self.evict_overflow();
    }

    pub(crate) fn clear(&mut self) {
        self.lines.clear();
    }

    pub(crate) fn lines(&self) -> &[LogLine] {
        &self.lines
    }

    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    fn evict_overflow(&mut self) {
        if self.lines.len() <= self.capacity {
            return;
        }
        let overflow = self.lines.len() - self.capacity;
        self.lines.drain(0..overflow);
    }

    #[doc(hidden)]
    pub fn replace_for_test(&mut self, lines: Vec<LogLine>) {
        self.lines = lines;
        self.evict_overflow();
    }

    #[doc(hidden)]
    pub fn lines_mut_for_test(&mut self) -> &mut [LogLine] {
        &mut self.lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub prefix: String,
    pub body: String,
    pub time_secs: u64,
}

impl LogLine {
    pub fn new(prefix: impl Into<String>, body: impl Into<String>) -> Self {
        let time_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        Self {
            prefix: prefix.into(),
            body: body.into(),
            time_secs,
        }
    }
}
