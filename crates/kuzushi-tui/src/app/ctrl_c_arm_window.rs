use super::*;

pub(crate) const CTRL_C_ARM_WINDOW: Duration = Duration::from_secs(2);

pub(crate) const THROTTLE_STALE_AFTER: Duration = Duration::from_secs(30);

/// How long a transient notice banner (error/warning) stays before it
/// auto-clears. Shorter than the throttle window — a notice is acknowledgement,
/// not a sustained status — but long enough to read.
pub(crate) const NOTICE_STALE_AFTER: Duration = Duration::from_secs(20);

pub(crate) const SPINNER_FRAME: Duration = Duration::from_millis(80);

/// Redraw cadence for the 3D playground (~20 fps). Faster than the spinner so
/// rotation looks smooth; only paid while a scene is open and unpaused.
pub(crate) const SCENE_FRAME: Duration = Duration::from_millis(50);

/// Idle camera spin speed in radians/second.
pub(crate) const SCENE_SPIN_RATE: f32 = 0.6;

/// How far one `h`/`l`/`j`/`k` keypress nudges the camera, in radians.
pub(crate) const SCENE_NUDGE: f32 = 0.18;

pub(crate) const VIEWPORT_PAGE_LINES: usize = 10;

pub(crate) const FINDINGS_PAGE_ROWS: usize = 10;
