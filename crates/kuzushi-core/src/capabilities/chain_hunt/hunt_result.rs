//! Tool-result payloads for the chain hunt.

use super::{chain_finding, HuntedChains, ModelChain};
use crate::structured_output::CostedStructuredJson;
use serde_json::{json, Value};

pub(super) fn empty_chain_hunt_result(confirmed_count: usize) -> Value {
    let summary = format!(
        "triage:chain-hunt — {confirmed_count} confirmed finding(s); need at least 2 to compose chains"
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
) -> Value {
    let chains: Vec<Value> = hunted.value.chains.iter().map(chain_json).collect();
    let summary = format!(
        "triage:chain-hunt — {} chain(s) composed from {} confirmed finding(s) ({} proposal(s) dropped)",
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
    });
    apply_hunt_cost(&mut data, hunted);
    let output = chain_hunt_output(&summary, &hunted.value.chains);
    let mut result = crate::module_result::completed_output_result(summary, output, data);
    apply_hunt_cost(&mut result, hunted);
    result
}

/// The summary plus each chain's title and member count.
fn chain_hunt_output(summary: &str, chains: &[ModelChain]) -> String {
    let lines = chains.iter().map(|chain| {
        format!("  - {} ({} findings)", chain.title, chain.members.len())
    });
    std::iter::once(summary.to_string())
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
            "summary\n  - Leaked key enables SQL injection (2 findings)"
        );
    }
}
