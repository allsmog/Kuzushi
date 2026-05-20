use super::*;

impl ShellApp {
    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(armed_at) = self.ctrl_c_armed_at {
            if Instant::now().duration_since(armed_at) > CTRL_C_ARM_WINDOW {
                self.ctrl_c_armed_at = None;
                changed = true;
            }
        }
        if let Some(throttle) = &self.advisory.throttle {
            if Instant::now().duration_since(throttle.since) > THROTTLE_STALE_AFTER {
                self.advisory.throttle = None;
                changed = true;
            }
        }
        if self.has_running_work() {
            // M4 §4.1: reduced-motion mode pauses the spinner. The
            // operator still sees the static frame plus the textual
            // status (`tool: active`) so progress is legible without
            // animation.
            let now = Instant::now();
            let due = self
                .last_spinner_advance
                .map(|prev| now.duration_since(prev) >= SPINNER_FRAME)
                .unwrap_or(true);
            if due && !crate::theme::active_theme().reduced_motion {
                self.spinner_phase = self.spinner_phase.wrapping_add(1);
                self.last_spinner_advance = Some(now);
                changed = true;
            }
        } else {
            self.last_spinner_advance = None;
        }
        changed
    }

    pub fn has_running_work(&self) -> bool {
        let scan_running = self.scan.as_ref().is_some_and(|scan| scan.running);
        let tool_running = self.tool_running.is_some();
        let agent_running = self.agent_chat.as_ref().is_some_and(|agent| agent.running);
        scan_running
            || tool_running
            || agent_running
            || self.planner_running
            || self.threat_worker_running
    }

    pub fn spinner_glyph(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[(self.spinner_phase as usize) % FRAMES.len()]
    }

    pub fn ctrl_c_armed(&self) -> bool {
        self.ctrl_c_armed_at
            .map(|armed_at| Instant::now().duration_since(armed_at) <= CTRL_C_ARM_WINDOW)
            .unwrap_or(false)
    }

    pub fn set_throttle(&mut self, source: impl Into<String>, message: impl Into<String>) {
        let source = source.into();
        let message = message.into();
        self.log("throttle", format!("{source}: {message}"));
        self.advisory.throttle = Some(ThrottleAdvisory {
            source,
            message,
            since: Instant::now(),
        });
    }

    pub fn clear_throttle(&mut self) {
        self.advisory.throttle = None;
    }

    pub fn is_budget_halted(&self) -> bool {
        self.advisory.budget_halt.is_some()
    }

    pub fn record_cost(&mut self, cost_usd: f64) {
        self.last_tool_cost_usd = Some(cost_usd);
        self.session_cost_usd += cost_usd;
        self.maybe_trigger_budget_halt();
    }
}
