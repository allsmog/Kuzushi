use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunbookBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_model_calls: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default)]
    pub spent_cost_usd: f64,
    #[serde(default)]
    pub model_calls: u32,
}

impl RunbookBudget {
    pub fn record_call(&mut self, cost_usd: f64) {
        self.spent_cost_usd += cost_usd.max(0.0);
        self.model_calls = self.model_calls.saturating_add(1);
    }

    pub fn remaining_cost_usd(&self) -> Option<f64> {
        self.max_cost_usd
            .map(|cap| (cap - self.spent_cost_usd).max(0.0))
    }

    pub fn exhausted(&self) -> bool {
        self.max_cost_usd
            .is_some_and(|cap| self.spent_cost_usd >= cap)
            || self
                .max_model_calls
                .is_some_and(|cap| self.model_calls >= cap)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDegradation {
    KeepVotes(u32),
    ReduceVotes { from: u32, to: u32 },
    SkipOptionalStep { step_id: String },
    MarkRemainingNeedsReview,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetDecision {
    pub exhausted: bool,
    pub degradation: BudgetDegradation,
    pub reason: String,
}

pub fn confirm_vote_degradation(requested_votes: u32, budget: &RunbookBudget) -> BudgetDecision {
    let requested_votes = normalize_odd_vote_count(requested_votes);
    if !budget.exhausted() {
        return BudgetDecision {
            exhausted: false,
            degradation: BudgetDegradation::KeepVotes(requested_votes),
            reason: "budget available".to_string(),
        };
    }

    let to = match requested_votes {
        vote if vote >= 5 => 3,
        3 => 1,
        _ => 0,
    };
    if to == 0 {
        BudgetDecision {
            exhausted: true,
            degradation: BudgetDegradation::MarkRemainingNeedsReview,
            reason: "budget exhausted after single-vote fallback".to_string(),
        }
    } else {
        BudgetDecision {
            exhausted: true,
            degradation: BudgetDegradation::ReduceVotes {
                from: requested_votes,
                to,
            },
            reason: format!("budget exhausted; reducing verifier votes from {requested_votes} to {to}"),
        }
    }
}

pub fn normalize_odd_vote_count(value: u32) -> u32 {
    match value {
        0 => 1,
        vote if vote % 2 == 1 => vote,
        vote => vote.saturating_sub(1).max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vote_counts_are_odd() {
        assert_eq!(normalize_odd_vote_count(0), 1);
        assert_eq!(normalize_odd_vote_count(2), 1);
        assert_eq!(normalize_odd_vote_count(4), 3);
        assert_eq!(normalize_odd_vote_count(5), 5);
    }

    #[test]
    fn exhausted_confirm_budget_degrades_votes() {
        let budget = RunbookBudget {
            max_model_calls: Some(0),
            ..Default::default()
        };
        let decision = confirm_vote_degradation(5, &budget);
        assert_eq!(
            decision.degradation,
            BudgetDegradation::ReduceVotes { from: 5, to: 3 }
        );
    }
}
