"""Smoothing, beta intervals, and calibration metrics.

The interval test uses Simpson-rule integration of the posterior density as an
independent oracle: two implementations of the same integral, one continued
fraction and one quadrature, must agree.
"""

import math
import unittest

from kuzushi_review_yield.calibration import (
    beta_credible_interval,
    beta_quantile,
    brier,
    ece,
    jeffreys_rate,
    regularized_incomplete_beta,
)


def beta_cdf_by_quadrature(x, alpha, beta, panels=20000):
    """Beta CDF by Simpson quadrature — an oracle independent of the module.

    Two adjustments keep plain quadrature honest. The symmetry
    `I_x(a, b) = 1 - I_{1-x}(b, a)` moves the integration to whichever tail is
    below one half. When `alpha < 1` the density is singular at 0, so the
    substitution `x = t ** (1 / alpha)` is applied, which cancels the
    `x ** (alpha - 1)` factor exactly; for `alpha >= 1` the density is smooth and
    the substitution would introduce a singular derivative instead of removing one.
    """
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    if x > 0.5:
        return 1.0 - beta_cdf_by_quadrature(1.0 - x, beta, alpha, panels)
    log_normalizer = math.lgamma(alpha + beta) - math.lgamma(alpha) - math.lgamma(beta)
    if alpha < 1.0:
        scale = math.exp(log_normalizer) / alpha
        integrand = lambda t: _power(1.0 - t ** (1.0 / alpha), beta - 1.0) * scale
        limit = x ** alpha
    else:
        normalizer = math.exp(log_normalizer)
        integrand = lambda t: (
            normalizer * _power(t, alpha - 1.0) * _power(1.0 - t, beta - 1.0)
        )
        limit = x
    return _simpson(integrand, limit, panels)


def _power(base, exponent):
    if base <= 0.0:
        return 0.0
    return base ** exponent


def _simpson(integrand, limit, panels):
    step = limit / panels
    total = integrand(0.0) + integrand(limit)
    for index in range(1, panels):
        total += integrand(index * step) * (4 if index % 2 else 2)
    return total * step / 3


class CalibrationTest(unittest.TestCase):
    def test_jeffreys_three_pos_zero_neg_not_100pct(self):
        self.assertAlmostEqual(jeffreys_rate(3, 0), 0.875, places=12)
        self.assertAlmostEqual(jeffreys_rate(0, 6), 0.071429, places=6)
        self.assertAlmostEqual(jeffreys_rate(1, 0), 0.75, places=12)

    def test_incomplete_beta_is_symmetric_at_the_median(self):
        self.assertAlmostEqual(regularized_incomplete_beta(0.5, 0.5, 0.5), 0.5, places=10)

    def test_beta_ci_matches_simpson_cdf(self):
        for positive, negative in [(3, 0), (12, 44), (0, 6), (31, 6)]:
            with self.subTest(counts=(positive, negative)):
                low, high = beta_credible_interval(positive, negative)
                alpha, beta = positive + 0.5, negative + 0.5
                self.assertAlmostEqual(
                    beta_cdf_by_quadrature(low, alpha, beta), 0.025, places=4
                )
                self.assertAlmostEqual(
                    beta_cdf_by_quadrature(high, alpha, beta), 0.975, places=4
                )

    def test_ci_contains_smoothed_rate(self):
        for positive, negative in [(3, 0), (12, 44), (0, 6), (55, 14)]:
            with self.subTest(counts=(positive, negative)):
                low, high = beta_credible_interval(positive, negative)
                rate = jeffreys_rate(positive, negative)
                self.assertLess(low, rate)
                self.assertLess(rate, high)

    def test_ci_narrows_as_support_grows(self):
        small = beta_credible_interval(3, 3)
        large = beta_credible_interval(300, 300)
        self.assertLess(large[1] - large[0], small[1] - small[0])

    def test_quantile_is_monotone(self):
        values = [beta_quantile(q / 10, 2.5, 4.5) for q in range(1, 10)]
        self.assertEqual(values, sorted(values))

    def test_brier_hand_case(self):
        # (0.9-1)^2 + (0.2-0)^2 + (0.6-1)^2 = 0.01 + 0.04 + 0.16 = 0.21; /3.
        self.assertAlmostEqual(brier([1, 0, 1], [0.9, 0.2, 0.6]), 0.07, places=12)

    def test_brier_rejects_mismatched_lengths(self):
        with self.assertRaises(ValueError):
            brier([1, 0], [0.5])

    def test_ece_perfect_calibration_zero(self):
        labels = [1] * 8 + [0] * 2
        scores = [0.8] * 10
        self.assertAlmostEqual(ece(labels, scores, bins=10), 0.0, places=12)

    def test_ece_reports_overconfidence(self):
        self.assertAlmostEqual(ece([0, 0, 0, 0], [0.9] * 4, bins=10), 0.9, places=12)


if __name__ == "__main__":
    unittest.main()
