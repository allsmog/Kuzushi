//! Shared progress primitives for long-running walks.

use std::time::{Duration, Instant};

/// Rate-limits progress emission from tight walk loops: `ready()` returns
/// true at most once per period, so a per-entry observer can emit a
/// heartbeat without flooding the trace or the terminal.
#[derive(Debug)]
pub struct HeartbeatGate {
    period: Duration,
    last: Instant,
}

impl HeartbeatGate {
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            last: Instant::now(),
        }
    }

    pub fn ready(&mut self) -> bool {
        if self.last.elapsed() >= self.period {
            self.last = Instant::now();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_period_gate_is_always_ready() {
        let mut gate = HeartbeatGate::new(Duration::ZERO);
        assert!(gate.ready());
        assert!(gate.ready());
    }

    #[test]
    fn unelapsed_period_holds_the_gate_closed() {
        let mut gate = HeartbeatGate::new(Duration::from_secs(3600));
        assert!(!gate.ready());
        assert!(!gate.ready());
    }
}
