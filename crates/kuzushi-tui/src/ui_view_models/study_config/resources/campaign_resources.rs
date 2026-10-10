use super::*;
use kuzushi_core::capabilities::campaign::StudyResourceEvidenceV1;

pub(super) fn lines(config: &BatchScanConfig) -> Option<Vec<String>> {
    let evidence = evidence(config)?;
    let projection = match evidence.project(config.study.max_job_attempts) {
        Ok(value) => value,
        Err(error) => return Some(vec![format!("Historical scenario unavailable: {error}")]),
    };
    let mut lines = vec![
        format!("Explicit prior study: {}", evidence.baseline_campaign_id),
        format!("Recorded plan digest: {}", evidence.baseline_plan_sha256),
        format!(
            "{} fixed cases · {} maximum job starts · {} cases without matching request evidence.",
            evidence.cases.len(),
            projection.starts,
            projection.uncalibrated_cases
        ),
    ];
    lines.extend(case_lines(evidence));
    lines.push(projection.provider_calls.map_or_else(
        || "Full plan provider-request scenario: unavailable; uncalibrated cases are not zero.".into(),
        |range| format!("Full plan historical scenario: {} to {} provider requests, including maximum starts per job.",range[0],range[1])));
    lines.push(projection.cost_usd.map_or_else(
        || {
            "Dollar estimate: unavailable. Unknown prices do not hide observed request counts."
                .into()
        },
        |range| {
            format!(
                "Historical dollar scenario: ${:.4} to ${:.4}.",
                range[0], range[1]
            )
        },
    ));
    lines.extend(projection.provider_calls.map_or_else(
        || uncalibrated_capacity_lines(config),
        |range| capacity_lines(config, Some(range[1])),
    ));
    lines.extend(["Historical complete passes describe the exact recorded conditions. Future turns, retries and failed starts may differ; this range is not an upper bound.".into(),
        "Calls and protected Review remain enforced independently. No dollar ceiling is enforced, no allowance is increased and no jobs are started by this preview.".into()]);
    Some(lines)
}

fn evidence(config: &BatchScanConfig) -> Option<&StudyResourceEvidenceV1> {
    config
        .study
        .scope_receipt
        .as_ref()
        .and_then(|receipt| receipt.resource_evidence.as_ref())
        .or_else(|| {
            config
                .study
                .matrix
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.resource_evidence.as_ref())
        })
}

fn case_lines(evidence: &StudyResourceEvidenceV1) -> Vec<String> {
    let mut lines = Vec::new();
    for case in &evidence.cases {
        lines.push(case_summary(case));
        lines.extend(
            case.limitations
                .iter()
                .map(|reason| format!("{}: {reason}", case.case_id)),
        );
    }
    lines
}

fn case_summary(case: &kuzushi_core::capabilities::campaign::CaseResourceEvidenceV1) -> String {
    let calls = case.calls_per_pass.map_or_else(
        || "requests unknown".into(),
        |range| format!("{} to {} observed requests per pass", range[0], range[1]),
    );
    format!(
        "{}: {} planned passes · {} matching complete samples · {calls}",
        case.case_id,
        case.passes,
        case.run_ids.len()
    )
}
