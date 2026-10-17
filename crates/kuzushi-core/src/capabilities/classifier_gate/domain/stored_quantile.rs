use super::{ClassifierConfig, QuantileEstimator};
use anyhow::{ensure, Result};

impl QuantileEstimator {
    pub(crate) fn validate_stored(&self) -> Result<()> {
        ClassifierConfig {
            target_percentile: self.p,
            ..Default::default()
        }
        .validate()?;
        ensure!(
            (self.count as u64) < (1_u64 << 53),
            "Classifier sample count exceeds exact numeric precision"
        );
        ensure!(
            self.q.iter().all(|value| (0.0..=1.0).contains(value)),
            "Classifier marker scores must be finite and within 0 to 1"
        );
        ensure!(
            self.marker_positions_are_valid(),
            "Classifier marker positions are invalid"
        );
        self.validate_adaptive_geometry()
    }

    fn marker_positions_are_valid(&self) -> bool {
        self.n[0] == 1.0
            && self.n[4] == self.count.max(5) as f64
            && self.n.windows(2).all(|pair| pair[0] < pair[1])
    }

    fn validate_adaptive_geometry(&self) -> Result<()> {
        if self.count >= 5 {
            ensure!(
                self.q.windows(2).all(|pair| pair[0] <= pair[1]),
                "Classifier marker scores are not ordered"
            );
        }
        ensure!(
            self.dn == Self::new(self.p).dn,
            "Classifier marker increments do not match the percentile"
        );
        ensure!(
            self.np
                .iter()
                .all(|value| (1.0..=self.n[4]).contains(value)),
            "Classifier desired positions are invalid"
        );
        Ok(())
    }
}
