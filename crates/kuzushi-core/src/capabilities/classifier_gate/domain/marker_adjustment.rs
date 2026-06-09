use super::QuantileEstimator;

pub(super) enum MarkerAdjustmentDirection {
    Forward,
    Backward,
}

pub(super) fn marker_adjustment_direction(d: f64) -> Option<MarkerAdjustmentDirection> {
    if d >= 1.0 {
        return Some(MarkerAdjustmentDirection::Forward);
    }
    (d <= -1.0).then_some(MarkerAdjustmentDirection::Backward)
}

pub(super) fn marker_has_adjustment_room(
    estimator: &QuantileEstimator,
    i: usize,
    direction: MarkerAdjustmentDirection,
) -> bool {
    match direction {
        MarkerAdjustmentDirection::Forward => estimator.n[i + 1] - estimator.n[i] > 1.0,
        MarkerAdjustmentDirection::Backward => estimator.n[i - 1] - estimator.n[i] < -1.0,
    }
}

pub(super) fn bounded_marker_height(
    estimator: &QuantileEstimator,
    i: usize,
    d_sign: f64,
    parabolic_height: f64,
) -> f64 {
    if marker_height_is_bounded(estimator, i, parabolic_height) { parabolic_height } else { estimator.linear(i, d_sign) }
}

fn marker_height_is_bounded(estimator: &QuantileEstimator, i: usize, height: f64) -> bool {
    estimator.q[i - 1] < height && height < estimator.q[i + 1]
}
