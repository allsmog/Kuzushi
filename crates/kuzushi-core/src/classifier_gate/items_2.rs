use super::prelude::*;
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

        // Initial fill: store the first 5 samples sorted.
        if self.count <= 5 {
            self.q[self.count - 1] = x;
            if self.count == 5 {
                self.q
                    .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            }
            return self.estimate();
        }

        // Find the cell `k` such that q[k] <= x < q[k+1].
        let k = if x < self.q[0] {
            self.q[0] = x;
            0
        } else if x < self.q[1] {
            0
        } else if x < self.q[2] {
            1
        } else if x < self.q[3] {
            2
        } else if x < self.q[4] {
            3
        } else {
            self.q[4] = x;
            3
        };

        // Increment positions.
        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }

        // Adjust marker heights.
        for i in 1..4 {
            let d = self.np[i] - self.n[i];
            if (d >= 1.0 && self.n[i + 1] - self.n[i] > 1.0)
                || (d <= -1.0 && self.n[i - 1] - self.n[i] < -1.0)
            {
                let d_sign = d.signum();
                let qp = self.parabolic(i, d_sign);
                if self.q[i - 1] < qp && qp < self.q[i + 1] {
                    self.q[i] = qp;
                } else {
                    self.q[i] = self.linear(i, d_sign);
                }
                self.n[i] += d_sign;
            }
        }

        self.estimate()
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

pub type Score = f32;

#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub target_percentile: f32,
    pub cold_start_floor: f32,
    pub cold_start_min_count: usize,
    /// Path to the SQLite DB used to persist the quantile across
    /// invocations. `None` = in-memory only (tests / dry runs).
    pub state_db: Option<std::path::PathBuf>,
}
