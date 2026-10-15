//! Tool-result payloads for the chain hunt.

use super::{chain_finding, HuntedChains, ModelChain};
use crate::structured_output::CostedStructuredJson;
use serde_json::{json, Value};

pub(super) fn empty_chain_hunt_result(confirmed_count: usize) -> Value {
    let summary = format!(
        "Confirmed base findings: {confirmed_count}; at least two are needed for relationship hypotheses"
    );
    crate::module_result::skipped_output_result(
        summary.clone(),
        summary.clone(),
        vec![json!(summary)],
        json!({"chains": [], "confirmedCount": confirmed_count}),
    )
}

pub(super) fn chain_hunt_result(
    hunted: &CostedStructuredJson<HuntedChains>,
    persisted: Option<crate::findings::GenericPersistedRun>,
    confirmed_count: usize,
    coverage: &super::inputs::InputCoverage,
) -> Value {
    let chains: Vec<Value> = hunted.value.chains.iter().map(chain_json).collect();
    let summary = format!(
        "Unreviewed relationship hypotheses: {} from {} confirmed findings; {} proposals rejected",
        chains.len(),
        confirmed_count,
        hunted.value.dropped,
    );
    let mut data = json!({
        "summary": summary,
        "chains": chains,
        "confirmedCount": confirmed_count,
        "droppedProposals": hunted.value.dropped,
        "persistedRunId": persisted.map(|run| run.run_id),
        "hypotheses":true,"relationshipsVerified":false,"sourceRevisionVerified":false,
        "inputCoverage":coverage,
    });
    apply_hunt_cost(&mut data, hunted);
    let output = chain_hunt_output(&summary, &hunted.value.chains);
    let mut result = if hunted.value.dropped > 0 || coverage.is_partial() {
        crate::module_result::partial_output_result(
            summary,
            output,
            vec![
                json!({"code":"partial-hypotheses","message":"Some proposals were rejected or ledger metadata was omitted. Every relationship still requires independent source review."}),
            ],
            data,
        )
    } else {
        crate::module_result::completed_output_result(summary, output, data)
    };
    apply_hunt_cost(&mut result, hunted);
    result
}

/// The summary plus each chain's title and member count.
fn chain_hunt_output(summary: &str, chains: &[ModelChain]) -> String {
    let lines = chains
        .iter()
        .map(|chain| format!("  - {} ({} findings)", chain.title, chain.members.len()));
    std::iter::once("Unreviewed relationship hypotheses. Finding metadata is not source verification; member verdicts remain unchanged.".to_string())
        .chain(std::iter::once(summary.to_string()))
        .chain(lines)
        .collect::<Vec<_>>()
        .join("\n")
}

fn chain_json(chain: &ModelChain) -> Value {
    json!({
        "id": chain_finding::model_chain_identity(chain),
        "title": chain.title,
        "members": chain.members.iter().map(|m| m.fingerprint.clone()).collect::<Vec<_>>(),
        "attackPath": chain.attack_path,
        "cumulativeImpact": chain.cumulative_impact,
        "whyThisChainMatters": chain.why_this_chain_matters,
        "detectionDifficulty": chain.detection_difficulty,
    })
}

fn apply_hunt_cost(target: &mut Value, hunted: &CostedStructuredJson<HuntedChains>) {
    if let Ok(cost) = hunted.cost_report() {
        crate::module_result::apply_runtime_cost_report(target, cost);
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;

    #[test]
    fn the_output_names_each_composed_chain() {
        let member = |fingerprint: &str| super::super::MemberRef {
            fingerprint: fingerprint.to_string(),
            title: "t".to_string(),
            file_path: "a.ts".to_string(),
            start_line: 1,
            severity: crate::findings::Severity::High,
            finding_id: None,
            scan_id: None,
        };
        let chain = ModelChain {
            title: "Leaked key enables SQL injection".to_string(),
            members: vec![member("a"), member("b")],
            attack_path: Vec::new(),
            cumulative_impact: String::new(),
            why_this_chain_matters: String::new(),
            detection_difficulty: String::new(),
        };

        assert_eq!(
            chain_hunt_output("summary", &[chain]),
            "Unreviewed relationship hypotheses. Finding metadata is not source verification; member verdicts remain unchanged.\nsummary\n  - Leaked key enables SQL injection (2 findings)"
        );
    }
}
