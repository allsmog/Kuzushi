use super::RunTraceStep;

impl RunTraceStep {
    pub fn new(n: usize, kind: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            n,
            kind: kind.into(),
            label: label.into(),
            latency_ms: None,
            cost_usd: None,
        }
    }

    pub fn with_latency_ms(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    pub fn with_cost_usd(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self
    }
}
