use kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot;
use serde_json::Value;

pub(crate) fn campaign_job_scope_label(job: &CampaignJobSnapshot) -> String {
    let scope = discovery_scope_label(&job.input, job.shard.as_deref());
    match job.threat_title.as_deref().or(job.threat_id.as_deref()) {
        Some(threat) => format!("{scope} / {threat}"),
        None => scope.to_string(),
    }
}

pub(crate) fn campaign_job_state_label(job: &CampaignJobSnapshot) -> &str {
    match (job.state.as_str(), job.reason.as_deref()) {
        ("parked", Some("canceled")) => "parked: canceled",
        _ => &job.state,
    }
}

pub(crate) fn campaign_job_detail_lines(job: &CampaignJobSnapshot) -> Vec<String> {
    let mut lines = vec![
        job.display_label.as_deref().unwrap_or(&job.job_id).into(),
        format!(
            "{} · {} · {}",
            job.tool.as_deref().unwrap_or("Tool not recorded"),
            campaign_job_state_label(job),
            campaign_job_attempt_summary(job)
        ),
        format!(
            "Findings: {}",
            job.findings
                .map(|n| n.to_string())
                .unwrap_or_else(|| "not recorded".into())
        ),
    ];
    lines.push(format!(
        "Current attempt counter: {}. Total attempts do not reset on resume.",
        job.attempts
    ));
    if job.dispatches.is_none() {
        lines.push("Lifetime attempt total unavailable for this legacy record.".into());
    }
    if let Some(reason) = &job.reason {
        lines.push(format!("Outcome: {reason}"));
    }
    lines.push(format!("Recorded cost: {}", campaign_job_cost_label(job)));
    lines.extend(recorded_selection_lines(job));
    lines.extend(recorded_context_lines(job));
    lines.push(format!("Job id: {}", job.job_id));
    lines.push(format!(
        "Run: {}",
        job.run_id.as_deref().unwrap_or("no run recorded")
    ));
    lines
}

pub(crate) fn campaign_job_attempt_summary(job: &CampaignJobSnapshot) -> String {
    let (count, kind) = match job.dispatches {
        Some(total) => (total, "total"),
        None => (job.attempts, "current"),
    };
    let noun = if count == 1 { "attempt" } else { "attempts" };
    format!("{count} {kind} {noun}")
}

pub(crate) fn campaign_job_attempt_cell(job: &CampaignJobSnapshot) -> String {
    match job.dispatches {
        Some(total) => total.to_string(),
        None => format!("{}?", job.attempts),
    }
}

pub(crate) fn campaign_job_cost_label(job: &CampaignJobSnapshot) -> String {
    if job.provider_spend_unresolved && job.cost_usd.is_some_and(|cost| cost <= 0.0) {
        return "unknown".into();
    }
    job.cost_usd
        .map(|cost| {
            if job.provider_spend_unresolved {
                format!("≥${cost:.2}")
            } else {
                format!("${cost:.2}")
            }
        })
        .unwrap_or_else(|| "unknown".into())
}

fn recorded_selection_lines(job: &CampaignJobSnapshot) -> Vec<String> {
    let model = job
        .input
        .get("model")
        .and_then(Value::as_str)
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "not supplied in this job".into());
    let engines = job
        .input
        .get("tasks")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "not recorded".into());
    vec![
        format!("Recorded model: {model}"),
        format!("Engines: {engines}"),
    ]
}

fn recorded_context_lines(job: &CampaignJobSnapshot) -> Vec<String> {
    [
        ("Discovery scope", "scanScopeRef"),
        ("Architecture context", "threatModelRef"),
        ("Supplemental context", "scanContextRef"),
    ]
    .into_iter()
    .flat_map(|(label, key)| binding_lines(label, job.input.get(key)))
    .collect()
}

fn binding_lines(label: &str, value: Option<&Value>) -> Vec<String> {
    match value {
        None => vec![format!("{label}: not recorded")],
        Some(Value::Null) => vec![format!("{label}: explicitly omitted")],
        Some(value) => {
            let text = serde_json::to_string_pretty(value)
                .unwrap_or_else(|_| "unreadable reference".into());
            let mut lines = vec![format!("{label}: recorded reference")];
            lines.extend(text.lines().map(|line| format!("  {line}")));
            lines
        }
    }
}

fn discovery_scope_label<'a>(input: &'a Value, legacy_shard: Option<&'a str>) -> &'a str {
    input
        .pointer("/scanScopeRef/scopeId")
        .and_then(Value::as_str)
        .or(legacy_shard)
        .unwrap_or("workspace")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn total_attempts_and_current_retry_count_are_distinct() {
        let root = tempfile::tempdir().unwrap();
        let dir = kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "attempts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plan.json"),
            json!({"jobs":[{"jobId":"one"}]}).to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.join("queue.json"),
            json!({"jobs":{"one":{"attempts":1,"dispatches":2}}}).to_string(),
        )
        .unwrap();
        let mut job = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
            root.path(),
            "attempts",
        )
        .unwrap()
        .jobs
        .remove(0);
        assert_eq!(campaign_job_attempt_summary(&job), "2 total attempts");
        let detail = campaign_job_detail_lines(&job).join("\n");
        assert!(detail.contains("Current attempt counter: 1"));
        job.dispatches = None;
        assert_eq!(campaign_job_attempt_cell(&job), "1?");
        assert!(campaign_job_detail_lines(&job)
            .join("\n")
            .contains("Lifetime attempt total unavailable"));
    }

    #[test]
    fn accepted_scope_precedes_legacy_shard() {
        let input = json!({"scanScopeRef": {"scopeId": "accepted-files"}});
        assert_eq!(
            discovery_scope_label(&input, Some("legacy")),
            "accepted-files"
        );
    }

    #[test]
    fn absent_scope_preserves_legacy_and_workspace_labels() {
        assert_eq!(
            discovery_scope_label(&Value::Null, Some("legacy")),
            "legacy"
        );
        assert_eq!(discovery_scope_label(&Value::Null, None), "workspace");
    }

    #[test]
    fn malformed_scope_does_not_manufacture_an_identity() {
        let input = json!({"scanScopeRef": {"scopeId": 7}});
        assert_eq!(discovery_scope_label(&input, None), "workspace");
    }
}
