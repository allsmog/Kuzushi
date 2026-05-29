use super::*;

pub(crate) const CTRL_C_ARM_WINDOW: Duration = Duration::from_secs(2);

pub(crate) const THROTTLE_STALE_AFTER: Duration = Duration::from_secs(30);

/// How long a transient notice banner (error/warning) stays before it
/// auto-clears. Shorter than the throttle window — a notice is acknowledgement,
/// not a sustained status — but long enough to read.
pub(crate) const NOTICE_STALE_AFTER: Duration = Duration::from_secs(20);

pub(crate) const SPINNER_FRAME: Duration = Duration::from_millis(80);

pub(crate) const VIEWPORT_PAGE_LINES: usize = 10;

pub(crate) const FINDINGS_PAGE_ROWS: usize = 10;
