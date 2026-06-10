//! An optional engagement time window (unix seconds).

use serde::{Deserialize, Serialize};

/// A testing window. Either bound may be omitted (open-ended on that side).
/// Outside the window every target is denied — a client engagement that ends
/// at 5pm Friday should not fire a play at 6pm.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeWindow {
    #[serde(default)]
    pub not_before_unix: Option<u64>,
    #[serde(default)]
    pub not_after_unix: Option<u64>,
}

impl ScopeWindow {
    pub fn contains(&self, now_unix: u64) -> bool {
        let after_start = self.not_before_unix.is_none_or(|start| now_unix >= start);
        let before_end = self.not_after_unix.is_none_or(|end| now_unix <= end);
        after_start && before_end
    }

    pub fn denial_reason(&self) -> String {
        match (self.not_before_unix, self.not_after_unix) {
            (Some(start), _) => format!("outside engagement window (opens at unix {start})"),
            (None, Some(end)) => format!("outside engagement window (closed at unix {end})"),
            (None, None) => "outside engagement window".to_string(),
        }
    }
}
