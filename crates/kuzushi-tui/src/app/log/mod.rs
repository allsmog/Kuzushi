pub(crate) use super::prelude::*;
pub(crate) use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

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
