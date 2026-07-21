//! Campaign-round summary decoding and time budgeting.

use anyhow::Result;
use serde_json::Value;
use std::time::Duration;

/// Wall-clock slack per round beyond the fuzz lane: the SymCC sync pass
/// (engine default cap 600 s) plus process/build overhead.
const ROUND_SYNC_SLACK_SECONDS: u64 = 600;
const ROUND_OVERHEAD_SECONDS: u64 = 120;

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundSummary {
    pub rounds_completed: u64,
    pub findings_recorded: u64,
    pub corpus_dir: Option<String>,
    pub disk_free_gb: Option<f64>,
    pub blockers: Vec<String>,
}

pub fn parse_round_summary(payload: &Value) -> RoundSummary {
    RoundSummary {
        rounds_completed: payload
            .get("rounds_completed")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        findings_recorded: payload
            .get("findings_recorded")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        corpus_dir: payload
            .get("corpus_dir")
            .and_then(Value::as_str)
            .map(str::to_string),
        disk_free_gb: payload.get("disk_free_gb").and_then(Value::as_f64),
        blockers: super::engine_cli::engine_blockers(payload),
    }
}

/// Refuse a round plan that cannot finish inside the tool deadline. The
/// check is explicit with the numbers in the error — silent truncation of
/// paid fuzzing time is worse than making the operator restate the budget.
pub fn round_budget(
    rounds: u64,
    fuzz_seconds: u64,
    target_count: u64,
    timeout: Duration,
) -> Result<()> {
    let per_round = fuzz_seconds + ROUND_SYNC_SLACK_SECONDS + ROUND_OVERHEAD_SECONDS;
    let needed = rounds
        .saturating_mul(per_round)
        .saturating_mul(target_count.max(1));
    let available = (timeout.as_secs() as f64 * 0.9) as u64;
    anyhow::ensure!(
        needed <= available,
        "fuzz round plan needs ~{needed}s ({rounds} round(s) x ({fuzz_seconds}s fuzz + \
         {ROUND_SYNC_SLACK_SECONDS}s sync + {ROUND_OVERHEAD_SECONDS}s overhead) x \
         {target_count} target(s)) but only {available}s fit inside 90% of timeoutMs — \
         raise timeoutMs or lower rounds/fuzzSeconds/afeTarget scope",
        target_count = target_count.max(1),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_summary_decodes_engine_payload_fields() {
        let summary = parse_round_summary(&json!({
            "rounds_completed": 2,
            "findings_recorded": 1,
            "corpus_dir": "/ws/work/vhdx/seeds",
            "disk_free_gb": 42.5,
            "blockers": ["klee image missing"],
        }));

        assert_eq!(summary.rounds_completed, 2);
        assert_eq!(summary.findings_recorded, 1);
        assert_eq!(summary.corpus_dir.as_deref(), Some("/ws/work/vhdx/seeds"));
        assert_eq!(summary.disk_free_gb, Some(42.5));
        assert_eq!(summary.blockers, vec!["klee image missing"]);

        let empty = parse_round_summary(&json!({}));
        assert_eq!(empty.rounds_completed, 0);
        assert!(empty.blockers.is_empty());
    }

    #[test]
    fn round_budget_accepts_defaults_and_rejects_overcommit_with_numbers() {
        round_budget(1, 600, 1, Duration::from_millis(3_600_000)).unwrap();

        let error = round_budget(6, 1800, 4, Duration::from_millis(3_600_000))
            .unwrap_err()
            .to_string();
        assert!(error.contains("raise timeoutMs"), "{error}");
        assert!(error.contains("6 round(s)"), "{error}");
        assert!(error.contains("4 target(s)"), "{error}");
    }

    #[test]
    fn round_budget_treats_zero_targets_as_one() {
        round_budget(1, 600, 0, Duration::from_millis(3_600_000)).unwrap();
    }
}
