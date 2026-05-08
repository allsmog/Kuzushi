use super::marker_adjustment::{
    bounded_marker_height, marker_adjustment_direction, marker_has_adjustment_room,
};
use super::*;

impl QuantileEstimator {
    pub fn new(p: f32) -> Self {
        let p = p.clamp(0.0, 1.0) as f64;
        Self {
            p: p as f32,
            q: [0.0; 5],
            n: [1.0, 2.0, 3.0, 4.0, 5.0],
            np: [1.0, 1.0 + 2.0 * p, 1.0 + 4.0 * p, 3.0 + 2.0 * p, 5.0],
            dn: [0.0, p / 2.0, p, (1.0 + p) / 2.0, 1.0],
            count: 0,
        }
    }

    /// Add a sample. Returns the current estimate.
    pub fn observe(&mut self, x: f32) -> f32 {
        let x = x as f64;
        self.count += 1;

        if self.observe_initial_sample(x) {
            return self.estimate();
        }

        let k = self.marker_cell_for(x);
        self.increment_marker_positions(k);
        self.adjust_marker_heights();

        self.estimate()
    }

    pub(crate) fn observe_initial_sample(&mut self, x: f64) -> bool {
        if self.count > 5 {
            return false;
        }

        self.q[self.count - 1] = x;
        if self.count == 5 {
            self.q
                .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        }
        true
    }

    pub(crate) fn marker_cell_for(&mut self, x: f64) -> usize {
        if x < self.q[0] {
            self.q[0] = x;
            return 0;
        }
        if x >= self.q[4] {
            self.q[4] = x;
            return 3;
        }
        self.q[1..4].partition_point(|boundary| x >= *boundary)
    }

    pub(crate) fn increment_marker_positions(&mut self, k: usize) {
        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }
    }

    pub(crate) fn adjust_marker_heights(&mut self) {
        for i in 1..4 {
            let d = self.np[i] - self.n[i];
            self.adjust_marker_height(i, d);
        }
    }

    pub(crate) fn adjust_marker_height(&mut self, i: usize, d: f64) {
        if !self.marker_needs_adjustment(i, d) {
            return;
        }

        let d_sign = d.signum();
        self.apply_marker_height_adjustment(i, d_sign);
    }

    fn apply_marker_height_adjustment(&mut self, i: usize, d_sign: f64) {
        let qp = self.parabolic(i, d_sign);
        self.q[i] = bounded_marker_height(self, i, d_sign, qp);
        self.n[i] += d_sign;
    }

    pub(crate) fn marker_needs_adjustment(&self, i: usize, d: f64) -> bool {
        marker_adjustment_direction(d)
            .is_some_and(|direction| marker_has_adjustment_room(self, i, direction))
    }

    pub(crate) fn parabolic(&self, i: usize, d: f64) -> f64 {
        let n = self.n;
        let q = self.q;
        q[i] + d / (n[i + 1] - n[i - 1])
            * ((n[i] - n[i - 1] + d) * (q[i + 1] - q[i]) / (n[i + 1] - n[i])
                + (n[i + 1] - n[i] - d) * (q[i] - q[i - 1]) / (n[i] - n[i - 1]))
    }

    pub(crate) fn linear(&self, i: usize, d: f64) -> f64 {
        let next = if d > 0.0 { i + 1 } else { i - 1 };
        self.q[i] + d * (self.q[next] - self.q[i]) / (self.n[next] - self.n[i])
    }

    /// Current estimate of the p-th quantile.
    pub fn estimate(&self) -> f32 {
        if self.count == 0 {
            return 0.0;
        }
        if self.count <= 5 {
            // For partial fills, sort the populated prefix and return the
            // closest stored value to the target percentile.
            let mut sorted: Vec<f64> = self.q[..self.count].to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let idx = ((self.p as f64) * (self.count as f64 - 1.0)).round() as usize;
            return sorted[idx.min(self.count - 1)] as f32;
        }
        self.q[2] as f32
    }
}
