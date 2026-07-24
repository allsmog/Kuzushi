use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Provider-reported token usage carried beside an existing runtime value.
///
/// Counts are observed lower bounds. The per-direction reported-call counts
/// record how many model calls supplied each token count, while `total_calls`
/// records how many calls actually occurred. This keeps an
/// explicit provider-reported `0 / 0` distinct from unavailable usage and
/// preserves known counts when only part of a multi-round loop was reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub input_reported_calls: u64,
    pub output_reported_calls: u64,
    pub total_calls: u64,
}

impl ModelTokenUsage {
    pub const fn reported(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            input_reported_calls: 1,
            output_reported_calls: 1,
            total_calls: 1,
        }
    }

    pub const fn unavailable_call() -> Self {
        Self {
            input_tokens: 0,
            output_tokens: 0,
            input_reported_calls: 0,
            output_reported_calls: 0,
            total_calls: 1,
        }
    }

    pub fn from_reported_options(input_tokens: Option<u64>, output_tokens: Option<u64>) -> Self {
        Self {
            input_tokens: input_tokens.unwrap_or(0),
            output_tokens: output_tokens.unwrap_or(0),
            input_reported_calls: u64::from(input_tokens.is_some()),
            output_reported_calls: u64::from(output_tokens.is_some()),
            total_calls: 1,
        }
    }

    pub fn from_aggregate(
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        input_reported_calls: u64,
        output_reported_calls: u64,
        total_calls: u64,
    ) -> Result<Self> {
        anyhow::ensure!(total_calls > 0, "model usage aggregate must include a model call");
        validate_reported_direction(input_tokens, input_reported_calls, total_calls, "input")?;
        validate_reported_direction(
            output_tokens,
            output_reported_calls,
            total_calls,
            "output",
        )?;
        Ok(Self {
            input_tokens: input_tokens.unwrap_or(0),
            output_tokens: output_tokens.unwrap_or(0),
            input_reported_calls,
            output_reported_calls,
            total_calls,
        })
    }

    pub fn checked_add(self, other: Self, context: &str) -> Result<Self> {
        Ok(Self {
            input_tokens: checked_add(self.input_tokens, other.input_tokens, context, "input")?,
            output_tokens: checked_add(self.output_tokens, other.output_tokens, context, "output")?,
            input_reported_calls: checked_add(
                self.input_reported_calls,
                other.input_reported_calls,
                context,
                "input reported-call",
            )?,
            output_reported_calls: checked_add(
                self.output_reported_calls,
                other.output_reported_calls,
                context,
                "output reported-call",
            )?,
            total_calls: checked_add(self.total_calls, other.total_calls, context, "total call")?,
        })
    }

    pub const fn is_complete(self) -> bool {
        self.total_calls > 0
            && self.input_reported_calls == self.total_calls
            && self.output_reported_calls == self.total_calls
    }

    pub const fn is_unavailable(self) -> bool {
        self.input_reported_calls == 0 && self.output_reported_calls == 0
    }

    /// Return observed counts when at least one represented call reported
    /// usage. For incomplete aggregates these are honest lower bounds.
    pub const fn observed_counts(self) -> (Option<u64>, Option<u64>) {
        let input = if self.input_reported_calls == 0 {
            None
        } else {
            Some(self.input_tokens)
        };
        let output = if self.output_reported_calls == 0 {
            None
        } else {
            Some(self.output_tokens)
        };
        (input, output)
    }

    pub const fn fully_reported_calls(self) -> u64 {
        if self.input_reported_calls < self.output_reported_calls {
            self.input_reported_calls
        } else {
            self.output_reported_calls
        }
    }
}

fn validate_reported_direction(
    tokens: Option<u64>,
    reported_calls: u64,
    total_calls: u64,
    direction: &str,
) -> Result<()> {
    anyhow::ensure!(
        reported_calls <= total_calls,
        "{direction} reported-call count exceeds total model calls"
    );
    anyhow::ensure!(
        tokens.is_some() == (reported_calls > 0),
        "{direction} token total and reported-call provenance disagree"
    );
    Ok(())
}

fn checked_add(left: u64, right: u64, context: &str, field: &str) -> Result<u64> {
    left.checked_add(right)
        .with_context(|| format!("{context} {field} token usage overflow"))
}

/// A runtime value plus safe numeric telemetry for the model call or calls
/// that produced it. Existing public response/step/outcome shapes stay
/// unchanged; runtimes that do not implement observed APIs receive an
/// unavailable one-call receipt through the compatibility constructors.
#[derive(Debug, Clone, PartialEq)]
pub struct Observed<T> {
    pub value: T,
    pub usage: ModelTokenUsage,
}

impl<T> Observed<T> {
    pub const fn new(value: T, usage: ModelTokenUsage) -> Self {
        Self { value, usage }
    }

    pub const fn without_usage(value: T) -> Self {
        Self::new(value, ModelTokenUsage::unavailable_call())
    }

    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> Observed<U> {
        Observed::new(map(self.value), self.usage)
    }

    pub fn try_map<U>(self, map: impl FnOnce(T) -> Result<U>) -> Result<Observed<U>> {
        Ok(Observed::new(map(self.value)?, self.usage))
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_zero_is_distinct_from_unavailable() {
        let reported = ModelTokenUsage::reported(0, 0);
        let unavailable = ModelTokenUsage::unavailable_call();

        assert_eq!(reported.observed_counts(), (Some(0), Some(0)));
        assert!(reported.is_complete());
        assert_eq!(unavailable.observed_counts(), (None, None));
        assert!(unavailable.is_unavailable());
    }

    #[test]
    fn aggregation_preserves_lower_bound_and_marks_missing_calls() {
        let usage = ModelTokenUsage::reported(12, 3)
            .checked_add(ModelTokenUsage::unavailable_call(), "test aggregate")
            .unwrap();

        assert_eq!(usage.observed_counts(), (Some(12), Some(3)));
        assert_eq!(usage.fully_reported_calls(), 1);
        assert_eq!(usage.total_calls, 2);
        assert!(!usage.is_complete());
        assert!(!usage.is_unavailable());
    }

    #[test]
    fn one_reported_direction_is_not_erased() {
        let usage = ModelTokenUsage::from_reported_options(Some(5), None);

        assert_eq!(usage.observed_counts(), (Some(5), None));
        assert!(!usage.is_complete());
        assert!(!usage.is_unavailable());
    }

    #[test]
    fn aggregation_rejects_overflow() {
        let left = ModelTokenUsage {
            input_tokens: u64::MAX,
            ..ModelTokenUsage::reported(0, 0)
        };

        assert!(left
            .checked_add(ModelTokenUsage::reported(1, 0), "test aggregate")
            .is_err());
    }

    #[test]
    fn aggregate_constructor_preserves_partial_provenance() {
        let usage = ModelTokenUsage::from_aggregate(Some(12), Some(3), 1, 1, 2).unwrap();

        assert_eq!(usage.observed_counts(), (Some(12), Some(3)));
        assert_eq!(usage.total_calls, 2);
        assert!(!usage.is_complete());
    }

    #[test]
    fn aggregate_constructor_rejects_dishonest_provenance() {
        assert!(ModelTokenUsage::from_aggregate(Some(12), None, 0, 0, 1).is_err());
        assert!(ModelTokenUsage::from_aggregate(None, None, 2, 0, 1).is_err());
    }
}
