use super::*;

/// Fold independent triage votes into one consensus outcome.
///
/// A strict majority (> n/2 votes on the same verdict) wins and keeps the
/// mean confidence of the winning votes; anything else — ties, three-way
/// splits — downgrades to `needs_review`, because disagreement between
/// equally-informed passes IS the signal that the evidence is ambiguous.
/// Costs always sum across every vote taken.
pub(in crate::modules) fn consensus_outcome(mut votes: Vec<TriageOutcome>) -> TriageOutcome {
    if votes.len() == 1 {
        return votes.remove(0);
    }
    let total = votes.len();
    let (cost_usd, cost_usd_exact) = summed_vote_cost(&votes);
    let tally = vote_tally(&votes);
    let outcome = match majority_verdict(&tally, total) {
        Some(verdict) => majority_outcome(&votes, verdict, total),
        None => split_outcome(&votes, total),
    };
    TriageOutcome {
        cost_usd,
        cost_usd_exact,
        ..outcome
    }
}

fn summed_vote_cost(votes: &[TriageOutcome]) -> (f64, bool) {
    let cost = votes.iter().map(|vote| vote.cost_usd).sum();
    let exact = votes.iter().all(|vote| vote.cost_usd_exact);
    (cost, exact)
}

fn vote_tally(votes: &[TriageOutcome]) -> Vec<(TriageVerdict, usize)> {
    let mut tally: Vec<(TriageVerdict, usize)> = Vec::new();
    for vote in votes {
        match tally.iter_mut().find(|(verdict, _)| *verdict == vote.verdict) {
            Some((_, count)) => *count += 1,
            None => tally.push((vote.verdict, 1)),
        }
    }
    tally
}

fn majority_verdict(tally: &[(TriageVerdict, usize)], total: usize) -> Option<TriageVerdict> {
    tally
        .iter()
        .find(|(_, count)| *count * 2 > total)
        .map(|(verdict, _)| *verdict)
}

fn majority_outcome(votes: &[TriageOutcome], verdict: TriageVerdict, total: usize) -> TriageOutcome {
    let winners: Vec<&TriageOutcome> = votes.iter().filter(|vote| vote.verdict == verdict).collect();
    let confidence = winners.iter().map(|vote| vote.confidence).sum::<f32>() / winners.len() as f32;
    TriageOutcome {
        verdict,
        confidence,
        rationale: format!(
            "consensus {}/{} {}: {}",
            winners.len(),
            total,
            verdict.as_str(),
            winners[0].rationale
        ),
        cost_usd: 0.0,
        cost_usd_exact: true,
    }
}

fn split_outcome(votes: &[TriageOutcome], total: usize) -> TriageOutcome {
    let breakdown = votes
        .iter()
        .map(|vote| vote.verdict.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    TriageOutcome {
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.0,
        rationale: format!(
            "no consensus across {total} votes ({breakdown}); disagreement between independent passes means the evidence is ambiguous"
        ),
        cost_usd: 0.0,
        cost_usd_exact: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(verdict: TriageVerdict, confidence: f32, cost: f64) -> TriageOutcome {
        TriageOutcome {
            verdict,
            confidence,
            rationale: format!("{} rationale", verdict.as_str()),
            cost_usd: cost,
            cost_usd_exact: true,
        }
    }

    #[test]
    fn single_vote_passes_through_unchanged() {
        let outcome = consensus_outcome(vec![vote(TriageVerdict::TruePositive, 0.9, 0.01)]);
        assert_eq!(outcome.verdict, TriageVerdict::TruePositive);
        assert_eq!(outcome.rationale, "true_positive rationale");
    }

    #[test]
    fn two_of_three_majority_wins_with_mean_confidence_and_summed_cost() {
        let outcome = consensus_outcome(vec![
            vote(TriageVerdict::TruePositive, 0.8, 0.01),
            vote(TriageVerdict::FalsePositive, 0.9, 0.02),
            vote(TriageVerdict::TruePositive, 0.6, 0.03),
        ]);
        assert_eq!(outcome.verdict, TriageVerdict::TruePositive);
        assert!((outcome.confidence - 0.7).abs() < 1e-6);
        assert!((outcome.cost_usd - 0.06).abs() < 1e-9);
        assert!(outcome.rationale.starts_with("consensus 2/3 true_positive:"));
    }

    #[test]
    fn disagreement_downgrades_to_needs_review() {
        let outcome = consensus_outcome(vec![
            vote(TriageVerdict::TruePositive, 0.9, 0.01),
            vote(TriageVerdict::FalsePositive, 0.9, 0.01),
            vote(TriageVerdict::ByDesign, 0.9, 0.01),
        ]);
        assert_eq!(outcome.verdict, TriageVerdict::NeedsReview);
        assert_eq!(outcome.confidence, 0.0);
        assert!(outcome.rationale.contains("no consensus across 3 votes"));
        assert!((outcome.cost_usd - 0.03).abs() < 1e-9);
    }

    #[test]
    fn even_split_is_not_a_majority() {
        let outcome = consensus_outcome(vec![
            vote(TriageVerdict::TruePositive, 0.9, 0.0),
            vote(TriageVerdict::FalsePositive, 0.9, 0.0),
        ]);
        assert_eq!(outcome.verdict, TriageVerdict::NeedsReview);
    }

    #[test]
    fn incomplete_cost_in_any_vote_marks_the_sum_inexact() {
        let mut second = vote(TriageVerdict::TruePositive, 0.9, 0.01);
        second.cost_usd_exact = false;
        let outcome =
            consensus_outcome(vec![vote(TriageVerdict::TruePositive, 0.9, 0.01), second]);
        assert!(!outcome.cost_usd_exact);
    }
}
