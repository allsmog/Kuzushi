const LANCZOS_COEFFICIENTS: [f64; 8] = [
    676.520_368_121_885_1,
    -1_259.139_216_722_402_8,
    771.323_428_777_653_1,
    -176.615_029_162_140_6,
    12.507_343_278_686_905,
    -0.138_571_095_265_720_12,
    9.984_369_578_019_572e-6,
    1.505_632_735_149_311_6e-7,
];

pub(super) fn beta_quantile(probability: f64, alpha: f64, beta: f64) -> f64 {
    if probability <= 0.0 {
        return 0.0;
    }
    if probability >= 1.0 {
        return 1.0;
    }
    binary_search_quantile(probability, alpha, beta)
}

fn binary_search_quantile(probability: f64, alpha: f64, beta: f64) -> f64 {
    let (mut low, mut high) = (0.0, 1.0);
    for _ in 0..64 {
        let middle = (low + high) / 2.0;
        if regularized_beta(middle, alpha, beta) < probability {
            low = middle;
        } else {
            high = middle;
        }
    }
    (low + high) / 2.0
}

fn regularized_beta(x: f64, alpha: f64, beta: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let front = beta_front(x, alpha, beta);
    let threshold = (alpha + 1.0) / (alpha + beta + 2.0);
    if x < threshold {
        front * beta_fraction(x, alpha, beta) / alpha
    } else {
        1.0 - front * beta_fraction(1.0 - x, beta, alpha) / beta
    }
}

fn beta_front(x: f64, alpha: f64, beta: f64) -> f64 {
    (alpha * x.ln() + beta * (-x).ln_1p() - log_beta(alpha, beta)).exp()
}

fn beta_fraction(x: f64, alpha: f64, beta: f64) -> f64 {
    let mut state = FractionState::new(x, alpha, beta);
    for iteration in 1..=160 {
        let delta = state.advance(iteration, x, alpha, beta);
        if (delta - 1.0).abs() <= 3.0e-14 {
            break;
        }
    }
    state.value
}

struct FractionState {
    value: f64,
    c: f64,
    d: f64,
}

impl FractionState {
    fn new(x: f64, alpha: f64, beta: f64) -> Self {
        let d = reciprocal_clamped(1.0 - (alpha + beta) * x / (alpha + 1.0));
        Self {
            value: d,
            c: 1.0,
            d,
        }
    }

    fn advance(&mut self, iteration: usize, x: f64, alpha: f64, beta: f64) -> f64 {
        let iteration = iteration as f64;
        let even = iteration * (beta - iteration) * x
            / ((alpha + 2.0 * iteration - 1.0) * (alpha + 2.0 * iteration));
        self.apply(even);
        let odd = -(alpha + iteration) * (alpha + beta + iteration) * x
            / ((alpha + 2.0 * iteration) * (alpha + 2.0 * iteration + 1.0));
        self.apply(odd)
    }

    fn apply(&mut self, coefficient: f64) -> f64 {
        self.d = reciprocal_clamped(1.0 + coefficient * self.d);
        self.c = clamp_small(1.0 + coefficient / self.c);
        let delta = self.c * self.d;
        self.value *= delta;
        delta
    }
}

fn reciprocal_clamped(value: f64) -> f64 {
    1.0 / clamp_small(value)
}

fn clamp_small(value: f64) -> f64 {
    if value.abs() < 1.0e-300 {
        1.0e-300
    } else {
        value
    }
}

fn log_beta(alpha: f64, beta: f64) -> f64 {
    log_gamma(alpha) + log_gamma(beta) - log_gamma(alpha + beta)
}

fn log_gamma(value: f64) -> f64 {
    let shifted = value - 1.0;
    let series = LANCZOS_COEFFICIENTS
        .iter()
        .enumerate()
        .fold(0.999_999_999_999_809_9, |sum, (index, coefficient)| {
            sum + coefficient / (shifted + index as f64 + 1.0)
        });
    let scale = shifted + 7.5;
    0.918_938_533_204_672_7 + (shifted + 0.5) * scale.ln() - scale + series.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_beta_quantiles_match_probability() {
        assert!((beta_quantile(0.05, 1.0, 1.0) - 0.05).abs() < 1.0e-10);
        assert!((beta_quantile(0.95, 1.0, 1.0) - 0.95).abs() < 1.0e-10);
    }

    #[test]
    fn symmetric_beta_interval_is_symmetric() {
        let low = beta_quantile(0.05, 6.0, 6.0);
        let high = beta_quantile(0.95, 6.0, 6.0);
        assert!((low - (1.0 - high)).abs() < 1.0e-10);
        assert!(low < 0.5 && high > 0.5);
    }
}
